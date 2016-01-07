/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "vmcs.h"

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
 * Trap/fault mnemonics.
 */
#define TRAP_divide_error      0
#define TRAP_debug             1
#define TRAP_nmi               2
#define TRAP_int3              3
#define TRAP_overflow          4
#define TRAP_bounds            5
#define TRAP_invalid_op        6
#define TRAP_no_device         7
#define TRAP_double_fault      8
#define TRAP_copro_seg         9
#define TRAP_invalid_tss      10
#define TRAP_no_segment       11
#define TRAP_stack_error      12
#define TRAP_gp_fault         13
#define TRAP_page_fault       14
#define TRAP_spurious_int     15
#define TRAP_copro_error      16
#define TRAP_alignment_check  17
#define TRAP_machine_check    18
#define TRAP_simd_error       19
#define TRAP_deferred_nmi     31

#define EFER_LME     (1<<8)
#define EFER_LMA     (1<<10)

/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001      /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002      /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004      /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008      /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010      /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020      /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000      /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000      /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000      /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000      /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000      /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		    0x0001  /* enable vm86 extensions */
#define X86_CR4_PVI		    0x0002  /* virtual interrupts flag enable */
#define X86_CR4_TSD		    0x0004  /* disable time stamp at ipl 3 */
#define X86_CR4_DE		    0x0008  /* enable debugging extensions */
#define X86_CR4_PSE		    0x0010  /* enable page size extensions */
#define X86_CR4_PAE		    0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		    0x0040  /* Machine check enable */
#define X86_CR4_PGE		    0x0080  /* enable global pages */
#define X86_CR4_PCE		    0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */

#define BTS64(b)					(1i64 << b)
#define FEATURE_CONTROL_LOCKED        BTS64(0)
#define FEATURE_CONTROL_VMXON_ENABLED BTS64(2)

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_FEATURE_CONTROL 	0x03a
#define MSR_IA32_DEBUGCTL			0x1d9
#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_VMX_PINBASED_CTLS	0x481
#define MSR_IA32_VMX_PROCBASED_CTLS	0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176

/* x86-64 MSR */
#define MSR_EFER            0xc0000080        /* extended feature register */
#define MSR_STAR            0xc0000081        /* legacy mode SYSCALL target */
#define MSR_LSTAR           0xc0000082        /* long mode SYSCALL target */
#define MSR_CSTAR           0xc0000083        /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK    0xc0000084        /* EFLAGS mask for syscall */

#define MSR_FS_BASE         0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE         0xc0000101        /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 

ULONG64 get_cr4 (
);

VOID set_in_cr4 (
  ULONG32 mask
);

VOID clear_in_cr4 (
  ULONG32 mask
);

#include "hvm.h"

//Implemented in vmx-asm.asm
VOID VmxVmCall (
  ULONG32 HypercallNumber
);

VOID VmxPtrld (
  PHYSICAL_ADDRESS VmcsPA
);

VOID VmxPtrst (
  PHYSICAL_ADDRESS VmcsPA
);

VOID VmxClear (
  PHYSICAL_ADDRESS VmcsPA
);

ULONG64 VmxRead (
  ULONG64 field
);

VOID VmxTurnOff ();

VOID VmxTurnOn (
  PHYSICAL_ADDRESS VmxonPA
);

VOID VmxResume ();

VOID VmxVMexitHandler (
  VOID
);

VOID VmxDumpShadowVmcs (
  PULONG64 PShadowVmcs
);

VOID VmxDumpVmcs ();

BOOLEAN VmxIsImplemented ();

NTSTATUS VmxSetupGeneralInterceptions (
  PCPU Cpu
);

BOOLEAN VmxIsNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID VmxDispatchNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID VmxAdjustRip (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 Delta
);

NTSTATUS VmxInitialize (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
);

NTSTATUS VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

NTSTATUS VmxVirtualize (
  PCPU Cpu
);

BOOLEAN VmxIsTrapVaild (
  ULONG TrappedVmExit
);

NTSTATUS VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
);

VOID VmxCrash (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID DumpMemory (
  PUCHAR Addr,
  ULONG64 Len
);