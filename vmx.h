/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "vmcs.h"
#include "hvm.h"

/*
 * VMX Exit Reasons
 */

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7

#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32

#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34

#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40

#define EXIT_REASON_MACHINE_CHECK       41

#define EXIT_REASON_TPR_BELOW_THRESHOLD 43

#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_TPR_BELOW_THRESHOLD

enum SEGREGS
{
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR
};

/*
 * Exit Qualifications for MOV for Control Register Access
 */
#define CONTROL_REG_ACCESS_NUM          0xf     /* 3:0, number of control register */
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose register */
#define LMSW_SOURCE_DATA                (0xFFFF << 16)  /* 16:31 lmsw source */

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_DR          (0 << 4)
#define TYPE_MOV_FROM_DR        (1 << 4)
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)
#define TYPE_CLTS               (2 << 4)
#define TYPE_LMSW               (3 << 4)

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */
#define BTS64(b)					(1i64 << b)
#define FEATURE_CONTROL_LOCKED        BTS64(0)
#define FEATURE_CONTROL_VMXON_ENABLED BTS64(2)

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_FEATURE_CONTROL 	0x03a
#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_VMX_PINBASED_CTLS	0x481
#define MSR_IA32_VMX_PROCBASED_CTLS	0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

#define MSR_LSTAR           0xC0000082

#define MSR_FS_BASE         0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE         0xc0000101        /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 

VOID set_in_cr4 (
  ULONG32 mask
);

VOID clear_in_cr4 (
  ULONG32 mask
);

//Implemented in vmx-asm.asm
VOID  VmxVmCall (
  ULONG32 HypercallNumber
);

ULONG64  VmxRead (
  ULONG64 field
);

VOID  VmxVmexitHandler ();

VOID  VmxDumpVmcs ();

BOOLEAN  VmxIsImplemented ();

NTSTATUS VmxSetupVMCS (
                       ULONG_PTR VMM_Stack,
                       PVOID GuestRip,
                       PVOID GuestRsp
                       );

NTSTATUS  VmxShutdown (
  PGUEST_REGS GuestRegs
);

NTSTATUS  VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
);

