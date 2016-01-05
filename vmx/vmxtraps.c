/* 
 * Copyright holder: Invisible Things Lab
 */

#include "vmxtraps.h"
#include "vmx.h"
#include "cpuid.h"
#include "kbdcap.h"

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
#include "../misc/scancode.h"
#endif

static BOOLEAN NTAPI VmxDispatchVmxInstrDummy (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;
  ULONG32 exit_qualification;

  if (!Cpu || !GuestRegs)
    return TRUE;

  _KdPrint (("VmxDispatchVminstructionDummy(): Nested virtualization not supported in this build!\n"));

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  Trap->General.RipDelta = inst_len;

  exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);

  __vmx_vmwrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & (~0x8d5) | 0x1 /* VMFailInvalid */ );
  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchHypercall (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;
  ULONG32 exit_qualification;

  if (!Cpu || !GuestRegs)
    return TRUE;

  _KdPrint (("VmxDispatchVminstructionDummy(): Nested virtualization not supported in this build!\n"));

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  Trap->General.RipDelta = inst_len;

  HcDispatchHypercall(Cpu, GuestRegs);

  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchMsrRead (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  ecx = (ULONG32) GuestRegs->rcx;

  switch (ecx) {
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
  case MSR_EFER:
    MsrValue.QuadPart = Cpu->Vmx.GuestEFER;
    //_KdPrint(("Guestip 0x%llx MSR_EFER Read 0x%llx 0x%llx \n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart));
    break;
  default:
    MsrValue.QuadPart = __readmsr (ecx);
  }

  GuestRegs->rax = MsrValue.LowPart;
  GuestRegs->rdx = MsrValue.HighPart;

  return TRUE;
}

static BOOLEAN NTAPI VmxDispatchMsrWrite (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  LARGE_INTEGER MsrValue;
  ULONG32 ecx;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  ecx = (ULONG32) GuestRegs->rcx;

  MsrValue.LowPart = (ULONG32) GuestRegs->rax;
  MsrValue.HighPart = (ULONG32) GuestRegs->rdx;

  switch (ecx) {
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
  case MSR_EFER:
    //_KdPrint(("Guestip 0x%llx MSR_EFER write 0x%llx 0x%llx\n",VmxRead(GUEST_RIP),ecx,MsrValue.QuadPart)); 
    Cpu->Vmx.GuestEFER = MsrValue.QuadPart;
    MsrWrite (MSR_EFER, (MsrValue.QuadPart) | EFER_LME);
    break;
  default:
    MsrWrite (ecx, MsrValue.QuadPart);
  }

  return TRUE;
}

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
static EjectCdrom (
  ULONG32 port
)
{
  CmIOOutB(port + 7, 0xa0);
  CmIOOutB(port, 0x1b);
  CmIOOutB(port, 0);
  CmIOOutB(port, 0);
  CmIOOutB(port, 0);
  CmIOOutB(port, 2);
  CmIOOutB(port, 0);
}

static BOOLEAN NTAPI VmxDispatchIoAccess (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG32 exit_qualification;
  ULONG32 port, size;
  ULONG32 direction, df, vm86;
  static ULONG32 ps2mode = 0x1;
  ULONG64 inst_len;

  if (!Cpu || !GuestRegs)
    return TRUE;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

  exit_qualification = (ULONG32) VmxRead (EXIT_QUALIFICATION);
  init_scancode ();

  // IO端口
  if (CmIsBitSet (exit_qualification, 6))
    port = (exit_qualification >> 16) & 0xFFFF;
  else
    port = ((ULONG32) (GuestRegs->rdx)) & 0xFFFF;

  //_KdPrint (("IO 0x%x IN 0x%x %c \n", port, GuestRegs->rax, scancode[GuestRegs->rax & 0xff]));

  size = (exit_qualification & 7) + 1;

  direction = CmIsBitSet (exit_qualification, 3);
  if (direction)  // 输入IN
  {
    GuestRegs->rax = CmIOIn (port);
    if (port == 0x64) {
      //
      // 读取状态字，判断是否有按键消息
      //
      if (GuestRegs->rax & 0x20)
        ps2mode = 0x1;          // 鼠标事件
      else
        ps2mode = 0;            // 键盘事件
    } else if (port == 0x60 && ps2mode == 0x0 && (GuestRegs->rax & 0xFF) < 0x80) {   // KeyUp = KeyDown + 0x80
      //
      // 如果键盘按下，读出扫描码
      //
      _KdPrint (("IO 0x%x IN 0x%x %c \n", port, GuestRegs->rax, scancode[GuestRegs->rax & 0xFF]));

      //GuestRegs->rax = 0;   // 拦截按键，不直接返回给Guest

# ifdef _X86_
      //Cpu->Vmx.GuestVMCS.GUEST_ES_SELECTOR = 0;
# endif
    }
  } else {
    //
    // 输出OUT
    //
    if (size == 1)
      CmIOOutB (port, (ULONG32) GuestRegs->rax);
    if (size == 2)
      CmIOOutW (port, (ULONG32) GuestRegs->rax);
    if (size == 4)
      CmIOOutD (port, (ULONG32) GuestRegs->rax);

    _KdPrint (("IO 0x%x OUT 0x%x size 0x%x\n", port, GuestRegs->rax, size));
  }

  return TRUE;
}
#endif

#ifdef INTERCEPT_RDTSCs
static BOOLEAN NTAPI VmxDispatchRdtsc (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len;

  inst_len = VmxRead (VM_EXIT_INSTRUCTION_LEN);
  if (Trap->General.RipDelta == 0)
    Trap->General.RipDelta = inst_len;

# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchRdtsc(): RDTSC intercepted, RIP: 0x%p\n", VmxRead (GUEST_RIP)));
# endif
  if (Cpu->Tracing > 0) {
    Cpu->Tsc = Cpu->EmulatedCycles + Cpu->LastTsc;
  } else {
    Cpu->Tsc = RegGetTSC ();
  }

# if DEBUG_LEVEL>2
  _KdPrint ((" Tracing = %d, LastTsc = %p, EmulatedCycles = %p, Tsc = %p\n",
             Cpu->Tracing, Cpu->LastTsc, Cpu->EmulatedCycles, Cpu->Tsc));
# endif

  Cpu->LastTsc = Cpu->Tsc;
  Cpu->EmulatedCycles = 0;
  Cpu->NoOfRecordedInstructions = 0;
  Cpu->Tracing = INSTR_TRACE_MAX;

  GuestRegs->rdx = (size_t) (Cpu->Tsc >> 32);
  GuestRegs->rax = (size_t) (Cpu->Tsc & 0xffffffff);
  __vmx_vmwrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) | 0x100);      // set TF

  return TRUE;
}

// FIXME: This looks like it needs reviewing -- compare with the SvmDispatchDB
static BOOLEAN NTAPI VmxDispatchException (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  PNBP_TRAP Trap,
  BOOLEAN WillBeAlsoHandledByGuestHv
)
{
  ULONG64 inst_len, uIntrInfo;

  if (!Cpu || !GuestRegs)
    return TRUE;

  uIntrInfo = VmxRead (VM_EXIT_INTR_INFO);
  if ((uIntrInfo & 0xff) != 1)
    // we accept only #DB here
    return TRUE;

//# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchException(): DB intercepted, RIP: 0x%p, INTR_INFO 0x%p, flags 0x%p, II 0x%p, PD 0x%p\n",
             VmxRead (GUEST_RIP), VmxRead (VM_EXIT_INTR_INFO), VmxRead (GUEST_RFLAGS),
             VmxRead (GUEST_INTERRUPTIBILITY_STATE), VmxRead (GUEST_PENDING_DBG_EXCEPTIONS)));
//# endif

  __vmx_vmwrite (GUEST_INTERRUPTIBILITY_STATE, 0);
  // FIXME: why is this commented?
//      if (RegGetDr6() & 0x40) {

# if DEBUG_LEVEL>2
  _KdPrint (("VmxDispatchException(): DB intercepted, RIP: 0x%p\n", VmxRead (GUEST_RIP)));
# endif

  Cpu->EmulatedCycles += 6;     // TODO: replace with f(Opcode)
  if (Cpu->Tracing-- <= 0)
    __vmx_vmwrite (GUEST_RFLAGS, VmxRead (GUEST_RFLAGS) & ~0x100);   // disable TF

  Cpu->NoOfRecordedInstructions++;
  //TODO: add instruction opcode to Cpu->RecordedInstructions[]

//      }       

  return TRUE;
}
#endif

//
// ------------------------------------------------------------------------------------
//

NTSTATUS NTAPI VmxRegisterTraps (
  PCPU Cpu
)
{
  NTSTATUS Status;
  PNBP_TRAP Trap;

#ifndef VMX_SUPPORT_NESTED_VIRTUALIZATION
  // used to set dummy handler for all VMX intercepts when we compile without nested support
  ULONG32 i, TableOfVmxExits[] = {
    EXIT_REASON_VMCALL,
    EXIT_REASON_VMCALL,
    EXIT_REASON_VMLAUNCH,
    EXIT_REASON_VMRESUME,
    EXIT_REASON_VMPTRLD,
    EXIT_REASON_VMPTRST,
    EXIT_REASON_VMREAD,
    EXIT_REASON_VMWRITE,
    EXIT_REASON_VMXON,
    EXIT_REASON_VMXOFF
  };
#endif

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_MSR_READ, 0,      // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchMsrRead, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchMsrRead with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_MSR_WRITE, 0,     // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchMsrWrite, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchMsrWrite with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  //
  // 为所有VM指令造成的VMExit设置一个无用的处理函数，VMCALL则作为Hypercall处理
  //
  for (i = 0; i < sizeof (TableOfVmxExits) / sizeof (ULONG32); i++) {
    if (TableOfVmxExits[i] == EXIT_REASON_VMCALL) {
      if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_VMCALL, 0,      // length of the instruction, 0 means length need to be get from vmcs later. 
                                                         VmxDispatchHypercall, &Trap))) {
        _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchHypercall with status 0x%08hX\n", Status));
        return Status;
      }
    } else {
      if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, TableOfVmxExits[i], 0,      // length of the instruction, 0 means length need to be get from vmcs later. 
                                                       VmxDispatchVmxInstrDummy, &Trap))) {
        _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchVmon with status 0x%08hX\n", Status));
        return Status;
      }
    }
    TrRegisterTrap (Cpu, Trap);
  }

#ifdef INTERCEPT_RDTSCs
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_EXCEPTION_NMI, 0, VmxDispatchException, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchException with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);

  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_RDTSC, 0, VmxDispatchRdtsc, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchRdtsc with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#endif

#ifdef VMX_ENABLE_PS2_KBD_SNIFFER
  if (!NT_SUCCESS (Status = TrInitializeGeneralTrap (Cpu, EXIT_REASON_IO_INSTRUCTION, 0,        // length of the instruction, 0 means length need to be get from vmcs later. 
                                                     VmxDispatchIoAccess, &Trap))) {
    _KdPrint (("VmxRegisterTraps(): Failed to register VmxDispatchIoAccess with status 0x%08hX\n", Status));
    return Status;
  }
  TrRegisterTrap (Cpu, Trap);
#endif

  return STATUS_SUCCESS;
}
