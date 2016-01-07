/* 
 * Copyright holder: Invisible Things Lab
 */

#include "vmx.h"
#include "cpuid.h"
#include "hypercalls.h"

ULONG64 g_HostStackBaseAddress;
extern ULONG g_uSubvertedCPUs;

UCHAR vmwrite(size_t CtlCode, size_t Value)
{
    //KdPrint(("vmwrite %llx, %llx\n", CtlCode, Value));
    return __vmx_vmwrite(CtlCode, Value);
}

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
  return CmIsBitSet (ecx, 5);
}

VOID
VmExitHandler (
               PCPU Cpu,
               PGUEST_REGS GuestRegs
               )
{
    ULONG64 ExitReason;
    ULONG_PTR GuestEIP;
    ULONG_PTR inst_len;
    BOOLEAN WillBeAlsoHandledByGuestHv = FALSE;

    if (!Cpu || !GuestRegs)
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
#ifdef BP_KNOCK
        if (fn == BP_KNOCK_EAX)
        {
            KdPrint (("Magic knock received: %x\n", BP_KNOCK_EAX));
            GuestRegs->rax = 0x68686868;
        }
        else
#endif
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
        HcDispatchHypercall(Cpu, GuestRegs);
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
        case MSR_IA32_SYSENTER_CS:
            MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_CS);
            break;

        case MSR_IA32_SYSENTER_ESP:
            MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_ESP);
            break;
        case MSR_IA32_SYSENTER_EIP:
            MsrValue.QuadPart = VmxRead (GUEST_SYSENTER_EIP);
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
        case MSR_IA32_SYSENTER_CS:
            __vmx_vmwrite (GUEST_SYSENTER_CS, MsrValue.QuadPart);
            break;
        case MSR_IA32_SYSENTER_ESP:
            __vmx_vmwrite (GUEST_SYSENTER_ESP, MsrValue.QuadPart);
            break;
        case MSR_IA32_SYSENTER_EIP:
            __vmx_vmwrite (GUEST_SYSENTER_EIP, MsrValue.QuadPart);
            break;
        case MSR_GS_BASE:
            __vmx_vmwrite (GUEST_GS_BASE, MsrValue.QuadPart);
            break;
        case MSR_FS_BASE:
            __vmx_vmwrite (GUEST_FS_BASE, MsrValue.QuadPart);
            break;
        default:
            MsrWrite (ecx, MsrValue.QuadPart);
        }
    }
    else
    {
        KdPrint (("VmExitHandler(): failed for exitcode 0x%llX\n", ExitReason));
    }

    __vmx_vmwrite(GUEST_RIP, GuestEIP + inst_len);
}

static VOID NTAPI VmxDispatchNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  NTSTATUS Status;
  BOOLEAN bInterceptedByGuest;
  ULONG64 Exitcode;

  if (!Cpu || !GuestRegs)
    return;

  _KdPrint (("VmxDispatchNestedEvent(): DUMMY!!! This build doesn't support nested virtualization!\n"));

}

static BOOLEAN NTAPI VmxIsNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  return FALSE;                 // DUMMY!!! This build doesn't support nested virtualization!!!
}

static VOID NTAPI VmxAdjustRip (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 Delta
)
{
  __vmx_vmwrite (GUEST_RIP, VmxRead (GUEST_RIP) + Delta);
  return;
}

static ULONG32 NTAPI VmxAdjustControls (
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

NTSTATUS NTAPI VmxFillGuestSelectorData (
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

  vmwrite (GUEST_ES_SELECTOR + Segreg * 2, Selector);
  vmwrite (GUEST_ES_LIMIT    + Segreg * 2, SegmentSelector.limit);
  vmwrite (GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

  if ((Segreg == LDTR) || (Segreg == TR))
    // don't setup for FS/GS - their bases are stored in MSR values
    vmwrite (GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

  return STATUS_SUCCESS;
}

NTSTATUS VmxSetupVMCS (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
)
{
  SEGMENT_SELECTOR SegmentSelector;
  PVOID GdtBase = (PVOID) GetGdtBase ();

  if (!Cpu->Vmx.OriginalVmcs)
    return STATUS_INVALID_PARAMETER;

  __vmx_vmclear (&Cpu->Vmx.VMCS_PA);  // 取消当前的VMCS的激活状态
  __vmx_vmptrld (&Cpu->Vmx.VMCS_PA);  // 加载新的VMCS并设为激活状态

  /////////////////////////////////////////////////////////////////////////////
  /*64BIT Guest-Statel Fields. */
  vmwrite (VMCS_LINK_POINTER,      0xffffffff);
  vmwrite (VMCS_LINK_POINTER_HIGH, 0xffffffff);

  /*32BIT Control Fields. */  //disable Vmexit by Extern-interrupt,NMI and Virtual NMI
  vmwrite (PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PINBASED_CTLS));
  vmwrite (CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls (0, MSR_IA32_VMX_PROCBASED_CTLS));
  vmwrite (EXCEPTION_BITMAP, 0);
  vmwrite (VM_EXIT_CONTROLS,
            VmxAdjustControls (VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
  vmwrite (VM_ENTRY_CONTROLS, VmxAdjustControls (VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

  vmwrite (VM_EXIT_MSR_STORE_COUNT, 0);
  vmwrite (VM_EXIT_MSR_LOAD_COUNT,  0);
  vmwrite (VM_ENTRY_MSR_LOAD_COUNT, 0);
  vmwrite (VM_ENTRY_INTR_INFO_FIELD,0);
  vmwrite (GUEST_ACTIVITY_STATE,    0);   // 处于正常执行指令状态         
  
////////////////////////////////////////////////////////////////////////////////////////////////

  // SetCRx()
  vmwrite (CR0_GUEST_HOST_MASK, 0);            // disable vmexit 0f mov to cr0 all
  vmwrite (CR4_GUEST_HOST_MASK, X86_CR4_VMXE); // disable vmexit 0f mov to cr4 expect for X86_CR4_VMXE
  vmwrite (CR4_READ_SHADOW, __readcr4() & ~X86_CR4_VMXE);  // Cr4寄存器SHADOW里去掉X86_CR4_VMXE
  //
  vmwrite (GUEST_CR0, __readcr0 ());
  vmwrite (GUEST_CR3, __readcr3 ());
  vmwrite (GUEST_CR4, __readcr4 ());
  vmwrite (GUEST_DR7, 0x400);
  //
  vmwrite (HOST_CR0, __readcr0 ());
  vmwrite (HOST_CR3, __readcr3 ());
  vmwrite (HOST_CR4, __readcr4 ());

  // SetDT()
  vmwrite (GUEST_GDTR_LIMIT, GetGdtLimit ());
  vmwrite (GUEST_IDTR_LIMIT, GetIdtLimit ());
  vmwrite (GUEST_GDTR_BASE, (ULONG64) GdtBase);
  vmwrite (GUEST_IDTR_BASE, GetIdtBase ());
  //
  vmwrite (HOST_GDTR_BASE, (ULONG64) GdtBase);
  vmwrite (HOST_IDTR_BASE, (ULONG64) GetIdtBase ());

  // SetSysCall()
  vmwrite (GUEST_SYSENTER_CS,  __readmsr (MSR_IA32_SYSENTER_CS));
  vmwrite (GUEST_SYSENTER_ESP, __readmsr (MSR_IA32_SYSENTER_ESP));
  vmwrite (GUEST_SYSENTER_EIP, __readmsr (MSR_IA32_SYSENTER_EIP));
  //
  vmwrite (HOST_IA32_SYSENTER_CS,  __readmsr (MSR_IA32_SYSENTER_CS));
  vmwrite (HOST_IA32_SYSENTER_ESP, __readmsr (MSR_IA32_SYSENTER_ESP));
  vmwrite (HOST_IA32_SYSENTER_EIP, __readmsr (MSR_IA32_SYSENTER_EIP));

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
  vmwrite (GUEST_ES_BASE, 0);
  vmwrite (GUEST_CS_BASE, 0);
  vmwrite (GUEST_SS_BASE, 0);
  vmwrite (GUEST_DS_BASE, 0);
  vmwrite (GUEST_FS_BASE, __readmsr (MSR_FS_BASE));
  vmwrite (GUEST_GS_BASE, __readmsr (MSR_GS_BASE));
  //
  vmwrite (HOST_CS_SELECTOR, BP_GDT64_CODE);
  vmwrite (HOST_DS_SELECTOR, BP_GDT64_DATA);
  vmwrite (HOST_ES_SELECTOR, BP_GDT64_DATA);
  vmwrite (HOST_SS_SELECTOR, BP_GDT64_DATA);
  vmwrite (HOST_FS_SELECTOR, RegGetFs () & 0xf8);
  vmwrite (HOST_GS_SELECTOR, RegGetGs () & 0xf8);
  vmwrite (HOST_TR_SELECTOR, GetTrSelector () & 0xf8);
  //
  vmwrite (HOST_FS_BASE, __readmsr (MSR_FS_BASE));
  vmwrite (HOST_GS_BASE, __readmsr (MSR_GS_BASE));
  CmInitializeSegmentSelector (&SegmentSelector, GetTrSelector (), GdtBase);
  vmwrite (HOST_TR_BASE, SegmentSelector.base);

  /////////////////////////////////////////////////////////////////////////////
  vmwrite (GUEST_RSP, (ULONG64) GuestRsp);     //setup guest sp
  vmwrite (GUEST_RIP, (ULONG64) GuestRip);     //setup guest ip : common-asm CmResumeGuest
  vmwrite (GUEST_RFLAGS, RegGetRflags ());

  // HOST_RSP与HOST_RIP决定进入VMM的地址
  vmwrite (HOST_RSP, (ULONG64) Cpu);   //setup host sp at vmxLaunch(...)
  vmwrite (HOST_RIP, (ULONG64) VmxVMexitHandler);

  _KdPrint (("VmxSetupVMCS(): Exit\n"));

  return STATUS_SUCCESS;
}

// #define VmxWrite __vmx_vmwrite
// #define MsrRead  __readmsr
// #define RegGetCr0 __readcr0
// #define RegGetCr3 __readcr3
// #define RegGetCr4 __readcr4
// #define GUEST_INTERRUPTIBILITY_INFO GUEST_INTERRUPTIBILITY_STATE

NTSTATUS NTAPI VmxInitialize (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
)
{
    // 检查IA32_FEATURE_CONTROL寄存器的Lock位
    if (!(__readmsr(MSR_IA32_FEATURE_CONTROL) & FEATURE_CONTROL_LOCKED))
    {
        KdPrint(("VmxInitialize() IA32_FEATURE_CONTROL bit[0] = 0!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // 检查IA32_FEATURE_CONTROL寄存器的Enable VMX outside SMX位
    if (!(__readmsr(MSR_IA32_FEATURE_CONTROL) & FEATURE_CONTROL_VMXON_ENABLED))
    {
        KdPrint(("VmxInitialize() IA32_FEATURE_CONTROL bit[2] = 0!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    //
    // 为VMXON结构分配空间 (Allocate VMXON region)
    //
    Cpu->OriginaVmxonR = MmAllocateNonCachedMemory(PAGE_SIZE);
    if (!Cpu->OriginaVmxonR)
    {
        KdPrint (("VmxInitialize(): Failed to allocate memory for original VMXON\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (Cpu->OriginaVmxonR, PAGE_SIZE);
    Cpu->OriginalVmxonRPA = MmGetPhysicalAddress(Cpu->OriginaVmxonR);

    //
    // 为VMCS结构分配空间 (Allocate VMCS)
    //
    Cpu->OriginalVmcs = MmAllocateNonCachedMemory(PAGE_SIZE);
    if (!Cpu->OriginalVmcs)
    {
        KdPrint (("VmxInitialize(): Failed to allocate memory for original VMCS\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (Cpu->OriginalVmcs, PAGE_SIZE);
    Cpu->VMCS_PA = MmGetPhysicalAddress(Cpu->OriginalVmcs);

    set_in_cr4 (X86_CR4_VMXE);
    *(ULONG64 *) Cpu->OriginaVmxonR = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff); //set up vmcs_revision_id
    *(ULONG64 *) Cpu->OriginalVmcs  = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff); 

    if (__vmx_on (&Cpu->OriginalVmxonRPA))
    {
        _KdPrint (("VmxOn Failed!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    //============================= 配置VMCS ================================

    if ( VmxSetupVMCS (Cpu, GuestRip, GuestRsp) )
    {
        KdPrint (("VmxSetupVMCS() failed!"));
        VmxTurnOff ();
        clear_in_cr4 (X86_CR4_VMXE);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static VOID VmxGenerateTrampolineToGuest (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PUCHAR Trampoline
)
{
  ULONG uTrampolineSize = 0;
  ULONG64 NewRsp;

  if (!Cpu || !GuestRegs)
    return;

  // assume Trampoline buffer is big enough
  __vmx_vmwrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);     // disable TF

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, GuestRegs->rcx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, GuestRegs->rdx);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBX, GuestRegs->rbx);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBP, GuestRegs->rbp);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSI, GuestRegs->rsi);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDI, GuestRegs->rdi);

#ifndef _X86_
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R8, GuestRegs->r8);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R9, GuestRegs->r9);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R10, GuestRegs->r10);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R11, GuestRegs->r11);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R12, GuestRegs->r12);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R13, GuestRegs->r13);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R14, GuestRegs->r14);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R15, GuestRegs->r15);
#endif

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

  // construct stack frame for IRETD:
  // [TOS]        rip
  // [TOS+0x4]    cs
  // [TOS+0x8]    rflags

#ifndef _X86_
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_SS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, NewRsp);
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
#endif
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_RFLAGS));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead (GUEST_CS_SELECTOR));
  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX,
                    VmxRead (GUEST_RIP) + VmxRead (VM_EXIT_INSTRUCTION_LEN));

  CmGeneratePushReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);

  CmGenerateMovReg (&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, GuestRegs->rax);

#ifdef _X86_
  CmGenerateIretd (&Trampoline[uTrampolineSize], &uTrampolineSize);
#else
  CmGenerateIretq (&Trampoline[uTrampolineSize], &uTrampolineSize);
#endif

  // restore old GDTR
  CmReloadGdtr ((PVOID) VmxRead (GUEST_GDTR_BASE), (ULONG) VmxRead (GUEST_GDTR_LIMIT));

  MsrWrite (MSR_GS_BASE, VmxRead (GUEST_GS_BASE));
  MsrWrite (MSR_FS_BASE, VmxRead (GUEST_FS_BASE));

  // FIXME???
  // restore ds, es
//      CmSetDS((USHORT)VmxRead(GUEST_DS_SELECTOR));
//      CmSetES((USHORT)VmxRead(GUEST_ES_SELECTOR));

  // cs and ss must be the same with the guest OS in this implementation

  // restore old IDTR
  CmReloadIdtr ((PVOID) VmxRead (GUEST_IDTR_BASE), (ULONG) VmxRead (GUEST_IDTR_LIMIT));

  return;
}

static NTSTATUS NTAPI VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  UCHAR Trampoline[0x600];

  _KdPrint (("VmxShutdown(): CPU#%d\n", Cpu->ProcessorNumber));

#if DEBUG_LEVEL>2
  VmxDumpVmcs ();
#endif
  InterlockedDecrement (&g_uSubvertedCPUs);

  // The code should be updated to build an approproate trampoline to exit to any guest mode.
  VmxGenerateTrampolineToGuest (Cpu, GuestRegs, Trampoline);

  _KdPrint (("VmxShutdown(): Trampoline generated\n", Cpu->ProcessorNumber));
  VmxTurnOff ();
  clear_in_cr4 (X86_CR4_VMXE);
  ((VOID (*)()) & Trampoline) ();

  // never returns
  return STATUS_SUCCESS;
}

static BOOLEAN NTAPI VmxIsTrapVaild (
  ULONG TrappedVmExit
)
{
  if (TrappedVmExit > VMX_MAX_GUEST_VMEXIT)
    return FALSE;
  return TRUE;
}
