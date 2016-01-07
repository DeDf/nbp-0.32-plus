/* 
 * Copyright holder: Invisible Things Lab
 */

#include "hypercalls.h"

VOID HcDispatchHypercall (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
  ULONG32 HypercallNumber;
  ULONG32 HypercallResult = 0;

  HypercallNumber = (ULONG32) (GuestRegs->rdx & 0xffff);

  switch (HypercallNumber)
  {
  case NBP_HYPERCALL_UNLOAD:

    _KdPrint (("HcDispatchHypercall(): NBP_HYPERCALL_UNLOAD\n"));

    GuestRegs->rcx = NBP_MAGIC;
    GuestRegs->rdx = HypercallResult;

    // disable virtualization, resume guest, don't setup time bomb
    VmxShutdown (Cpu, GuestRegs);

    // never returns
    _KdPrint (("HcDispatchHypercall(): ArchShutdown() returned\n"));
    break;

  default:
    _KdPrint (("HcDispatchHypercall(): Unsupported hypercall 0x%04X\n", HypercallNumber));
    break;
  }

  GuestRegs->rcx = NBP_MAGIC;
  GuestRegs->rdx = HypercallResult;
}
