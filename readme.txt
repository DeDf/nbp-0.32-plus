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
VmxIsImplemented()  // ��⵱ǰ�Ĵ������Ƿ�֧��Vt
vmxtraps.c
VmxRegisterTraps ()