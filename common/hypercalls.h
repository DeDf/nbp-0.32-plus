/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "msr.h"
#include "regs.h"
#include "hvm.h"
#include "cpuid.h"

#define NBP_MAGIC ((ULONG32)'!LTI')

// these are 16-bit words
#define NBP_HYPERCALL_UNLOAD			0x1
#define NBP_HYPERCALL_QUEUE_INTERRUPT	0x2
#define NBP_HYPERCALL_EOI			    0x3

VOID NTAPI HcDispatchHypercall (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

NTSTATUS NTAPI HcMakeHypercall (
  ULONG32 HypercallNumber,
  ULONG32 HypercallParameter,
  PULONG32 pHypercallResult
);
