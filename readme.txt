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