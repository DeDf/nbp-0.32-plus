/* 
 * Copyright holder: Invisible Things Lab
 */

#include "newbp.h"

extern BOOLEAN g_bDisableComOutput;

NTSTATUS
DriverUnload (
  PDRIVER_OBJECT DriverObject
)
{
  g_bDisableComOutput = TRUE;

  if ( HvmSpitOutBluepill () )
  {
    KdPrint (("NEWBLUEPILL: HvmSpitOutBluepill() failed!\n"));
  }

// #ifdef USE_LOCAL_DBGPRINTS
//   DbgUnregisterWindow ();
// #endif

  KdPrint (("NEWBLUEPILL: Unloading finished\n"));
  return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry (
  PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath
)
{
  NTSTATUS status;

#ifdef USE_COM_PRINTS
  PioInit ((PUCHAR) COM_PORT_ADDRESS);
#endif
  ComInit ();

  //
  // 是否使用调试输出
  //
// #ifdef USE_LOCAL_DBGPRINTS
//   status = DbgRegisterWindow (g_BpId);
//   if (status)
//   {
//     _KdPrint (("NEWBLUEPILL: DbgRegisterWindow() failed with status 0x%08hX\n", status));
//     return status;
//   }
// #endif

  KdPrint (("\nNEWBLUEPILL DriverEntry~\n"));

  //
  // 初始化Hvm, 失败则撤销更改
  //
  status = HvmInit ();
  if (status)
  {
    _KdPrint (("NEWBLUEPILL: HvmInit() failed with status 0x%08hX\n", status));
// #ifdef USE_LOCAL_DBGPRINTS
//     DbgUnregisterWindow ();
// #endif
    return status;
  }

  KeInitializeMutex (&g_HvmMutex, 0);  // 初始化全局互斥体g_HvmMutex, 设置其状态为受信

  //
  // 鍚吞下BluePill，开启VMM模式, 失败则撤销更改
  //
  status = HvmSwallowBluepill ();
  if (status)
  {
    _KdPrint (("NEWBLUEPILL: HvmSwallowBluepill() failed with status 0x%08hX\n", status));
// #ifdef USE_LOCAL_DBGPRINTS
//     DbgUnregisterWindow ();
// #endif
    return status;
  }

  DriverObject->DriverUnload = DriverUnload;

  KdPrint (("NEWBLUEPILL: Initialization finished\n"));

  return STATUS_SUCCESS;
}
