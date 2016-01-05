HVM_DEPENDENT Vmx = {
  ARCH_VMX,
  VmxIsImplemented,
  VmxInitialize,
  VmxVirtualize,
  VmxShutdown,
  VmxIsNestedEvent,
  VmxDispatchNestedEvent,
  VmxDispatchEvent,
  VmxAdjustRip,
  VmxRegisterTraps,
  VmxIsTrapVaild
};

hvm.c
HvmSwallowBluepill()
HvmSubvertCpu()
vmc.c
VmxIsImplemented()  // 检测当前的处理器是否支持Vt
vmxtraps.c
VmxRegisterTraps ()

vmx.c
VmExitHandler() 处理VM-Exit

EXIT_REASON_CR_ACCESS 必须处理