/* 
 * Copyright holder: Invisible Things Lab
 */

#include "newbp.h"

VOID
DriverUnload (
    PDRIVER_OBJECT DriverObject
)
{
    if ( HvmSpitOutBluepill () )    // �³�ҩ����
        KdPrint (("[NEWBLUEPILL] HvmSpitOutBluepill() failed!\n"));
    else
        KdPrint (("[NEWBLUEPILL] Unloading finished~\n"));
}

NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    KdPrint (("\n[NEWBLUEPILL] DriverEntry~\n"));

    if (!VmxIsImplemented ())
    {
        KdPrint (("DriverEntry(): VMX is not supported!\n"));
        return STATUS_NOT_SUPPORTED;
    }
        
    if ( HvmSwallowBluepill () )    // ����ҩ����
    {
        KdPrint (("[NEWBLUEPILL] HvmSwallowBluepill() failed!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    DriverObject->DriverUnload = DriverUnload;

    KdPrint (("[NEWBLUEPILL] Initialization finished~\n"));
    return STATUS_SUCCESS;
}
