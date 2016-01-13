/* 
 * Copyright holder: Invisible Things Lab
 */

#include "vmx.h"

extern ULONG g_uSubvertedCPUs;

/********************************************************************
  检测当前的处理器是否支持Vt
********************************************************************/
BOOLEAN VmxIsImplemented ()
{
    ULONG32 eax, ebx, ecx, edx;
    GetCpuIdInfo (0, &eax, &ebx, &ecx, &edx);
    if (eax < 1)
    {
        KdPrint (("VmxIsImplemented(): Extended CPUID functions not implemented\n"));
        return FALSE;
    }

    if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69))
    {
        KdPrint (("VmxIsImplemented(): Not an INTEL processor\n"));
        return FALSE;
    }

    GetCpuIdInfo (0x1, &eax, &ebx, &ecx, &edx);
    return (ecx & (1<<5));
}

VOID
VmExitHandler (
  PGUEST_REGS GuestRegs
)
{
    ULONG64 ExitReason;
    ULONG_PTR GuestEIP;
    ULONG_PTR inst_len;
    BOOLEAN WillBeAlsoHandledByGuestHv = FALSE;

    if (!GuestRegs)
        return;

    __vmx_vmread(VM_EXIT_REASON, &ExitReason);
    //
    __vmx_vmread(GUEST_RIP, &GuestEIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);

    //KdPrint (("VmExitHandler(): ExitReason %x\n", ExitReason));

    if (ExitReason == EXIT_REASON_CPUID)
    {
        ULONG32 fn, eax, ebx, ecx, edx;

        fn = (ULONG32) GuestRegs->rax;

        if (fn == BP_KNOCK_EAX)
        {
            KdPrint (("Magic knock received: %x\n", BP_KNOCK_EAX));
            GuestRegs->rax = 0x68686868;
        }
        else
        {
            ecx = (ULONG32) GuestRegs->rcx;
            GetCpuIdInfo (fn, &eax, &ebx, &ecx, &edx);
            GuestRegs->rax = eax;
            GuestRegs->rbx = ebx;
            GuestRegs->rcx = ecx;
            GuestRegs->rdx = edx;
        }
    }
    else if (ExitReason == EXIT_REASON_INVD)
    {

    }
    else if (ExitReason == EXIT_REASON_VMCALL)
    {
        ULONG32 HypercallNumber = (ULONG32) (GuestRegs->rcx & 0xffff);

        switch (HypercallNumber)
        {
        case NBP_HYPERCALL_UNLOAD:

            GuestRegs->rcx = NBP_MAGIC;
            GuestRegs->rdx = 0;

            // disable virtualization, resume guest, don't setup time bomb
            VmxShutdown (GuestRegs);

            // never returns
            KdPrint (("HcDispatchHypercall(): ArchShutdown() returned\n"));
            break;

        default:
            KdPrint (("HcDispatchHypercall(): Unsupported hypercall 0x%04X\n", HypercallNumber));
            break;
        }

        GuestRegs->rcx = NBP_MAGIC;
        GuestRegs->rdx = 0;
    }
    else if (ExitReason >= EXIT_REASON_VMCLEAR && ExitReason <= EXIT_REASON_VMXON)
    {
        __vmx_vmwrite(GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & (~0x8d5) | 0x1 /* VMFailInvalid */ );
    }
    else if (ExitReason == EXIT_REASON_CR_ACCESS)
    {
        ULONG32 exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);
        ULONG32 gp = (exit_qualification & CONTROL_REG_ACCESS_REG) >> 8;
        ULONG32 cr =  exit_qualification & CONTROL_REG_ACCESS_NUM;

        switch (exit_qualification & CONTROL_REG_ACCESS_TYPE)
        {
        case TYPE_MOV_TO_CR:
            if (cr == 3)
                __vmx_vmwrite (GUEST_CR3, *((PULONG64) GuestRegs + gp));
            break;

        case TYPE_MOV_FROM_CR:
            if (cr == 3)
                __vmx_vmread(GUEST_CR3, (PULONG64) GuestRegs + gp);
            break;

            //   case TYPE_CLTS:
            //     break;
            //   case TYPE_LMSW:
            //     break;
        }
    }
    else if (ExitReason == EXIT_REASON_MSR_READ)
    {
        LARGE_INTEGER MsrValue;
        ULONG32 ecx = (ULONG32) GuestRegs->rcx;

        switch (ecx)
        {
        case MSR_LSTAR:
            KdPrint(("readmsr MSR_LSTAR\n"));
            MsrValue.QuadPart = __readmsr (MSR_LSTAR);
            break;
        case MSR_GS_BASE:
            MsrValue.QuadPart = VmxRead (GUEST_GS_BASE);
            break;
        case MSR_FS_BASE:
            MsrValue.QuadPart = VmxRead (GUEST_FS_BASE);
            break;
        default:
            MsrValue.QuadPart = __readmsr (ecx);
        }

        GuestRegs->rax = MsrValue.LowPart;
        GuestRegs->rdx = MsrValue.HighPart;
    }
    else if (ExitReason == EXIT_REASON_MSR_WRITE)
    {
        LARGE_INTEGER MsrValue;
        ULONG32 ecx = (ULONG32) GuestRegs->rcx;

        MsrValue.LowPart  = (ULONG32) GuestRegs->rax;
        MsrValue.HighPart = (ULONG32) GuestRegs->rdx;

        switch (ecx)
        {
        case MSR_LSTAR:
            KdPrint(("writemsr MSR_LSTAR\n"));
            __vmx_vmwrite (MSR_LSTAR, MsrValue.QuadPart);
            break;
        case MSR_GS_BASE:
            __vmx_vmwrite (GUEST_GS_BASE, MsrValue.QuadPart);
            break;
        case MSR_FS_BASE:
            __vmx_vmwrite (GUEST_FS_BASE, MsrValue.QuadPart);
            break;
        default:
            __writemsr (ecx, MsrValue.QuadPart);
        }
    }
    else
    {
        KdPrint (("VmExitHandler(): failed for exitcode 0x%llX\n", ExitReason));
    }

    __vmx_vmwrite(GUEST_RIP, GuestEIP + inst_len);
}

static ULONG32  VmxAdjustControls (
  ULONG32 Ctl,
  ULONG32 Msr
)
{
  LARGE_INTEGER MsrValue;

  MsrValue.QuadPart = __readmsr (Msr);
  Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
  Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
  return Ctl;
}

NTSTATUS  VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };
  ULONG uAccessRights;

  CmInitializeSegmentSelector (&SegmentSelector, Selector, GdtBase);
  uAccessRights = ((PUCHAR) & SegmentSelector.attributes)[0] + (((PUCHAR) & SegmentSelector.attributes)[1] << 12);

  if (!Selector)
    uAccessRights |= 0x10000;

  __vmx_vmwrite (GUEST_ES_SELECTOR + Segreg * 2, Selector);
  __vmx_vmwrite (GUEST_ES_LIMIT    + Segreg * 2, SegmentSelector.limit);
  __vmx_vmwrite (GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

  if ((Segreg == LDTR) || (Segreg == TR))
    // don't setup for FS/GS - their bases are stored in MSR values
    __vmx_vmwrite (GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

  return STATUS_SUCCESS;
}

NTSTATUS VmxSetupVMCS (
  ULONG_PTR VMM_Stack,
  PVOID GuestRip,
  PVOID GuestRsp
)
{
  SEGMENT_SELECTOR SegmentSelector;
  PVOID GdtBase = (PVOID) GetGdtBase ();

  /////////////////////////////////////////////////////////////////////////////
  /*64BIT Guest-Statel Fields. */
  __vmx_vmwrite (VMCS_LINK_POINTER,      0xffffffff);
  __vmx_vmwrite (VMCS_LINK_POINTER_HIGH, 0xffffffff);

  /*32BIT Control Fields. */  //disable Vmexit by Extern-interrupt,NMI and Virtual NMI
  __vmx_vmwrite (PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PINBASED_CTLS));
  __vmx_vmwrite (CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PROCBASED_CTLS));
  __vmx_vmwrite (EXCEPTION_BITMAP, 0);
  __vmx_vmwrite (VM_EXIT_CONTROLS,
            VmxAdjustControls (VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
  __vmx_vmwrite (VM_ENTRY_CONTROLS, VmxAdjustControls (VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

  __vmx_vmwrite (VM_EXIT_MSR_STORE_COUNT, 0);
  __vmx_vmwrite (VM_EXIT_MSR_LOAD_COUNT,  0);
  __vmx_vmwrite (VM_ENTRY_MSR_LOAD_COUNT, 0);
  __vmx_vmwrite (VM_ENTRY_INTR_INFO_FIELD,0);
  __vmx_vmwrite (GUEST_ACTIVITY_STATE,    0);   // 处于正常执行指令状态         
  
////////////////////////////////////////////////////////////////////////////////////////////////

  // SetCRx()
  __vmx_vmwrite (CR0_GUEST_HOST_MASK, 0);            // disable vmexit 0f mov to cr0 all
  __vmx_vmwrite (CR4_GUEST_HOST_MASK, X86_CR4_VMXE); // disable vmexit 0f mov to cr4 expect for X86_CR4_VMXE
  __vmx_vmwrite (CR4_READ_SHADOW, __readcr4() & ~X86_CR4_VMXE);  // Cr4寄存器SHADOW里去掉X86_CR4_VMXE
  //
  __vmx_vmwrite (GUEST_CR0, __readcr0 ());
  __vmx_vmwrite (GUEST_CR3, __readcr3 ());
  __vmx_vmwrite (GUEST_CR4, __readcr4 ());
  __vmx_vmwrite (GUEST_DR7, 0x400);
  //
  __vmx_vmwrite (HOST_CR0, __readcr0 ());
  __vmx_vmwrite (HOST_CR3, __readcr3 ());
  __vmx_vmwrite (HOST_CR4, __readcr4 ());

  // SetDT()
  __vmx_vmwrite (GUEST_GDTR_LIMIT, GetGdtLimit ());
  __vmx_vmwrite (GUEST_IDTR_LIMIT, GetIdtLimit ());
  __vmx_vmwrite (GUEST_GDTR_BASE, (ULONG64) GdtBase);
  __vmx_vmwrite (GUEST_IDTR_BASE, GetIdtBase ());
  //
  __vmx_vmwrite (HOST_GDTR_BASE, (ULONG64) GdtBase);
  __vmx_vmwrite (HOST_IDTR_BASE, (ULONG64) GetIdtBase ());

  // SetSegSelectors()
  VmxFillGuestSelectorData (GdtBase, ES, RegGetEs ());
  VmxFillGuestSelectorData (GdtBase, CS, RegGetCs ());
  VmxFillGuestSelectorData (GdtBase, SS, RegGetSs ());
  VmxFillGuestSelectorData (GdtBase, DS, RegGetDs ());
  VmxFillGuestSelectorData (GdtBase, FS, RegGetFs ());
  VmxFillGuestSelectorData (GdtBase, GS, RegGetGs ());
  VmxFillGuestSelectorData (GdtBase, LDTR, GetLdtr ());
  VmxFillGuestSelectorData (GdtBase, TR, GetTrSelector ());
  //
  __vmx_vmwrite (GUEST_ES_BASE, 0);
  __vmx_vmwrite (GUEST_CS_BASE, 0);
  __vmx_vmwrite (GUEST_SS_BASE, 0);
  __vmx_vmwrite (GUEST_DS_BASE, 0);
  __vmx_vmwrite (GUEST_FS_BASE, __readmsr (MSR_FS_BASE));
  __vmx_vmwrite (GUEST_GS_BASE, __readmsr (MSR_GS_BASE));
  //
  __vmx_vmwrite (HOST_CS_SELECTOR, BP_GDT64_CODE);
  __vmx_vmwrite (HOST_DS_SELECTOR, BP_GDT64_DATA);
  __vmx_vmwrite (HOST_ES_SELECTOR, BP_GDT64_DATA);
  __vmx_vmwrite (HOST_SS_SELECTOR, BP_GDT64_DATA);
  __vmx_vmwrite (HOST_FS_SELECTOR, RegGetFs () & 0xf8);
  __vmx_vmwrite (HOST_GS_SELECTOR, RegGetGs () & 0xf8);
  __vmx_vmwrite (HOST_TR_SELECTOR, GetTrSelector () & 0xf8);
  //
  __vmx_vmwrite (HOST_FS_BASE, __readmsr (MSR_FS_BASE));
  __vmx_vmwrite (HOST_GS_BASE, __readmsr (MSR_GS_BASE));
  CmInitializeSegmentSelector (&SegmentSelector, GetTrSelector (), GdtBase);
  __vmx_vmwrite (HOST_TR_BASE, SegmentSelector.base);

  /////////////////////////////////////////////////////////////////////////////
  __vmx_vmwrite (GUEST_RSP, (ULONG64) GuestRsp);     //setup guest sp
  __vmx_vmwrite (GUEST_RIP, (ULONG64) GuestRip);     //setup guest ip : common-asm CmResumeGuest
  __vmx_vmwrite (GUEST_RFLAGS, RegGetRflags ());

  // HOST_RSP与HOST_RIP决定进入VMM的地址
  __vmx_vmwrite (HOST_RSP, VMM_Stack);
  __vmx_vmwrite (HOST_RIP, (ULONG64) VmxVmexitHandler);

  return STATUS_SUCCESS;
}

VOID VmxGenerateTrampolineToGuest (
  PGUEST_REGS GuestRegs,
  PUCHAR Trampoline
)
{
  ULONG uTrampolineSize = 0;
  ULONG64 NewRsp;

  // assume Trampoline buffer is big enough
  __vmx_vmwrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);     // disable TF

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, GuestRegs->rcx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, GuestRegs->rdx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBX, GuestRegs->rbx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBP, GuestRegs->rbp);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSI, GuestRegs->rsi);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDI, GuestRegs->rdi);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R8,  GuestRegs->r8);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R9,  GuestRegs->r9);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R10, GuestRegs->r10);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R11, GuestRegs->r11);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R12, GuestRegs->r12);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R13, GuestRegs->r13);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R14, GuestRegs->r14);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R15, GuestRegs->r15);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR0, VmxRead (GUEST_CR0));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR3, VmxRead (GUEST_CR3));
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR4, VmxRead (GUEST_CR4));

  NewRsp = VmxRead (GUEST_RSP);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSP, NewRsp);

  // construct stack frame for IRETQ:
  // [TOS]        rip
  // [TOS+0x08]   cs
  // [TOS+0x10]   rflags
  // [TOS+0x18]   rsp
  // [TOS+0x20]   ss

  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_SS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, NewRsp);
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_RFLAGS));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_CS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_RIP) + VmxRead (VM_EXIT_INSTRUCTION_LEN));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg  (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, GuestRegs->rax);

  CmGenerateIretq (&Trampoline[uTrampolineSize], &uTrampolineSize);
}

NTSTATUS VmxShutdown (
  PGUEST_REGS GuestRegs
)
{
  UCHAR Trampoline[0x600];

  InterlockedDecrement (&g_uSubvertedCPUs);

  // The code should be updated to build an approproate trampoline to exit to any guest mode.
  VmxGenerateTrampolineToGuest (GuestRegs, Trampoline);

  __vmx_off ();
  clear_in_cr4 (X86_CR4_VMXE);

  ((VOID (*)()) &Trampoline) ();

  // never returns
  return STATUS_SUCCESS;
}
