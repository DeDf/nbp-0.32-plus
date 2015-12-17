/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "vmcs.h"

#define BTS(b)					(1i64 << b)
#define FEATURE_CONTROL_LOCKED        BTS(0)
#define FEATURE_CONTROL_VMXON_ENABLED BTS(2)

 enum VMEXIT_EXITCODE
{
  /* control register read exitcodes */
  VMEXIT_CR0_READ = 0,
  VMEXIT_CR1_READ = 1,
  VMEXIT_CR2_READ = 2,
  VMEXIT_CR3_READ = 3,
  VMEXIT_CR4_READ = 4,
  VMEXIT_CR5_READ = 5,
  VMEXIT_CR6_READ = 6,
  VMEXIT_CR7_READ = 7,
  VMEXIT_CR8_READ = 8,
  VMEXIT_CR9_READ = 9,
  VMEXIT_CR10_READ = 10,
  VMEXIT_CR11_READ = 11,
  VMEXIT_CR12_READ = 12,
  VMEXIT_CR13_READ = 13,
  VMEXIT_CR14_READ = 14,
  VMEXIT_CR15_READ = 15,

  /* control register write exitcodes */
  VMEXIT_CR0_WRITE = 16,
  VMEXIT_CR1_WRITE = 17,
  VMEXIT_CR2_WRITE = 18,
  VMEXIT_CR3_WRITE = 19,
  VMEXIT_CR4_WRITE = 20,
  VMEXIT_CR5_WRITE = 21,
  VMEXIT_CR6_WRITE = 22,
  VMEXIT_CR7_WRITE = 23,
  VMEXIT_CR8_WRITE = 24,
  VMEXIT_CR9_WRITE = 25,
  VMEXIT_CR10_WRITE = 26,
  VMEXIT_CR11_WRITE = 27,
  VMEXIT_CR12_WRITE = 28,
  VMEXIT_CR13_WRITE = 29,
  VMEXIT_CR14_WRITE = 30,
  VMEXIT_CR15_WRITE = 31,

  /* debug register read exitcodes */
  VMEXIT_DR0_READ = 32,
  VMEXIT_DR1_READ = 33,
  VMEXIT_DR2_READ = 34,
  VMEXIT_DR3_READ = 35,
  VMEXIT_DR4_READ = 36,
  VMEXIT_DR5_READ = 37,
  VMEXIT_DR6_READ = 38,
  VMEXIT_DR7_READ = 39,
  VMEXIT_DR8_READ = 40,
  VMEXIT_DR9_READ = 41,
  VMEXIT_DR10_READ = 42,
  VMEXIT_DR11_READ = 43,
  VMEXIT_DR12_READ = 44,
  VMEXIT_DR13_READ = 45,
  VMEXIT_DR14_READ = 46,
  VMEXIT_DR15_READ = 47,

  /* debug register write exitcodes */
  VMEXIT_DR0_WRITE = 48,
  VMEXIT_DR1_WRITE = 49,
  VMEXIT_DR2_WRITE = 50,
  VMEXIT_DR3_WRITE = 51,
  VMEXIT_DR4_WRITE = 52,
  VMEXIT_DR5_WRITE = 53,
  VMEXIT_DR6_WRITE = 54,
  VMEXIT_DR7_WRITE = 55,
  VMEXIT_DR8_WRITE = 56,
  VMEXIT_DR9_WRITE = 57,
  VMEXIT_DR10_WRITE = 58,
  VMEXIT_DR11_WRITE = 59,
  VMEXIT_DR12_WRITE = 60,
  VMEXIT_DR13_WRITE = 61,
  VMEXIT_DR14_WRITE = 62,
  VMEXIT_DR15_WRITE = 63,

  /* processor exception exitcodes (VMEXIT_EXCP[0-31]) */
  VMEXIT_EXCEPTION_DE = 64,     /* divide-by-zero-error */
  VMEXIT_EXCEPTION_DB = 65,     /* debug */
  VMEXIT_EXCEPTION_NMI = 66,    /* non-maskable-interrupt */
  VMEXIT_EXCEPTION_BP = 67,     /* breakpoint */
  VMEXIT_EXCEPTION_OF = 68,     /* overflow */
  VMEXIT_EXCEPTION_BR = 69,     /* bound-range */
  VMEXIT_EXCEPTION_UD = 70,     /* invalid-opcode */
  VMEXIT_EXCEPTION_NM = 71,     /* device-not-available */
  VMEXIT_EXCEPTION_DF = 72,     /* double-fault */
  VMEXIT_EXCEPTION_09 = 73,     /* unsupported (reserved) */
  VMEXIT_EXCEPTION_TS = 74,     /* invalid-tss */
  VMEXIT_EXCEPTION_NP = 75,     /* segment-not-present */
  VMEXIT_EXCEPTION_SS = 76,     /* stack */
  VMEXIT_EXCEPTION_GP = 77,     /* general-protection */
  VMEXIT_EXCEPTION_PF = 78,     /* page-fault */
  VMEXIT_EXCEPTION_15 = 79,     /* reserved */
  VMEXIT_EXCEPTION_MF = 80,     /* x87 floating-point exception-pending */
  VMEXIT_EXCEPTION_AC = 81,     /* alignment-check */
  VMEXIT_EXCEPTION_MC = 82,     /* machine-check */
  VMEXIT_EXCEPTION_XF = 83,     /* simd floating-point */

  /* exceptions 20-31 (exitcodes 84-95) are reserved */

  /* ...and the rest of the #VMEXITs */
  VMEXIT_INTR = 96,
  VMEXIT_NMI = 97,
  VMEXIT_SMI = 98,
  VMEXIT_INIT = 99,
  VMEXIT_VINTR = 100,
  VMEXIT_CR0_SEL_WRITE = 101,
  VMEXIT_IDTR_READ = 102,
  VMEXIT_GDTR_READ = 103,
  VMEXIT_LDTR_READ = 104,
  VMEXIT_TR_READ = 105,
  VMEXIT_IDTR_WRITE = 106,
  VMEXIT_GDTR_WRITE = 107,
  VMEXIT_LDTR_WRITE = 108,
  VMEXIT_TR_WRITE = 109,
  VMEXIT_RDTSC = 110,
  VMEXIT_RDPMC = 111,
  VMEXIT_PUSHF = 112,
  VMEXIT_POPF = 113,
  VMEXIT_CPUID = 114,
  VMEXIT_RSM = 115,
  VMEXIT_IRET = 116,
  VMEXIT_SWINT = 117,
  VMEXIT_INVD = 118,
  VMEXIT_PAUSE = 119,
  VMEXIT_HLT = 120,
  VMEXIT_INVLPG = 121,
  VMEXIT_INVLPGA = 122,
  VMEXIT_IOIO = 123,
  VMEXIT_MSR = 124,
  VMEXIT_TASK_SWITCH = 125,
  VMEXIT_FERR_FREEZE = 126,
  VMEXIT_SHUTDOWN = 127,
  VMEXIT_VMRUN = 128,
  VMEXIT_VMMCALL = 129,
  VMEXIT_VMLOAD = 130,
  VMEXIT_VMSAVE = 131,
  VMEXIT_STGI = 132,
  VMEXIT_CLGI = 133,
  VMEXIT_SKINIT = 134,
  VMEXIT_RDTSCP = 135,
  VMEXIT_ICEBP = 136,
  VMEXIT_WBINVD = 137,
  VMEXIT_NPF = 1024,            /* nested paging fault */
  VMEXIT_INVALID = -1
};

/*
 * VMX Exit Reasons
 */

#define VMX_EXIT_REASONS_FAILED_VMENTRY 0x80000000

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

typedef enum SEGREGS
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
#define X86_CR4_VME		0x0001  /* enable vm86 extensions */
#define X86_CR4_PVI		0x0002  /* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004  /* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008  /* enable debugging extensions */
#define X86_CR4_PSE		0x0010  /* enable page size extensions */
#define X86_CR4_PAE		0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		0x0040  /* Machine check enable */
#define X86_CR4_PGE		0x0080  /* enable global pages */
#define X86_CR4_PCE		0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */
        /* MSRs & bits used for VMX enabling */

#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

/* x86-64 MSR */

#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 

ULONG64 NTAPI get_cr4 (
);

VOID NTAPI set_in_cr4 (
  ULONG32 mask
);

VOID NTAPI clear_in_cr4 (
  ULONG32 mask
);

#define	VMX_VMCS_SIZE_IN_PAGES	1
#define	VMX_IOBitmap_SIZE_IN_PAGES	1
#define	VMX_MSRBitmap_SIZE_IN_PAGES	1

#define	VMX_VMXONR_SIZE_IN_PAGES	2

typedef struct _VMX
{
  PHYSICAL_ADDRESS VmcsToContinuePA;    // MUST go first in the structure; refer to SvmVmrun() for details
  PVOID _2mbVmcbMap;

  PHYSICAL_ADDRESS OriginalVmcsPA;
  PVOID OriginalVmcs;           // VMCS which was originally built by the BP for the guest OS
  PHYSICAL_ADDRESS OriginalVmxonRPA;    // Vmxon Region which was originally built by the BP for the guest OS
  PVOID OriginaVmxonR;

  PHYSICAL_ADDRESS IOBitmapAPA; // points to IOBitMapA.
  PVOID IOBitmapA;

  PHYSICAL_ADDRESS IOBitmapBPA; // points to IOBitMapB
  PVOID IOBitmapB;

  PHYSICAL_ADDRESS MSRBitmapPA; // points to MsrBitMap
  PVOID MSRBitmap;

  ULONG64 GuestCR0;             //Guest's CR0. 
  ULONG64 GuestCR3;             //Guest's CR3. for storing guest cr3 when guest diasble paging.
  ULONG64 GuestCR4;             //Guest's CR4. 
  ULONG64 GuestEFER;
  UCHAR GuestStateBeforeInterrupt[0xc00];

} VMX, *PVMX;

#include "hvm.h"

//Implemented in vmx-asm.asm
VOID NTAPI VmxVmCall (
  ULONG32 HypercallNumber
);

VOID NTAPI VmxPtrld (
  PHYSICAL_ADDRESS VmcsPA
);

VOID NTAPI VmxPtrst (
  PHYSICAL_ADDRESS VmcsPA
);

VOID NTAPI VmxClear (
  PHYSICAL_ADDRESS VmcsPA
);

ULONG64 NTAPI VmxRead (
  ULONG64 field
);

VOID NTAPI VmxTurnOff ();

VOID NTAPI VmxTurnOn (
  PHYSICAL_ADDRESS VmxonPA
);

VOID NTAPI VmxLaunch ();
VOID NTAPI VmxResume ();

VOID NTAPI VmxVmexitHandler (
  VOID
);

VOID NTAPI VmxDumpShadowVmcs (
  PULONG64 PShadowVmcs
);

VOID NTAPI VmxDumpVmcs (
);

BOOLEAN NTAPI VmxIsImplemented ();

NTSTATUS NTAPI VmxSetupGeneralInterceptions (
  PCPU Cpu
);

static BOOLEAN NTAPI VmxIsNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID NTAPI VmxDispatchEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

static VOID NTAPI VmxDispatchNestedEvent (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

static VOID NTAPI VmxAdjustRip (
  PCPU Cpu,
  PGUEST_REGS GuestRegs,
  ULONG64 Delta
);

NTSTATUS NTAPI VmxInitialize (
  PCPU Cpu,
  PVOID GuestRip,
  PVOID GuestRsp
);

static NTSTATUS NTAPI VmxShutdown (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

static NTSTATUS NTAPI VmxVirtualize (
  PCPU Cpu
);

static BOOLEAN NTAPI VmxIsTrapVaild (
  ULONG TrappedVmExit
);

NTSTATUS NTAPI VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
);

VOID NTAPI VmxCrash (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
);

VOID DumpMemory (
  PUCHAR Addr,
  ULONG64 Len
);

VOID VmxHandleInterception (
                            PCPU Cpu,
                            PGUEST_REGS GuestRegs,
                            BOOLEAN WillBeAlsoHandledByGuestHv
                            );