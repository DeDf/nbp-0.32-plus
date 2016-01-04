/* 
 * Copyright holder: Invisible Things Lab
 */

#include "newbp.h"

VOID
DriverUnload (
    PDRIVER_OBJECT DriverObject
)
{
    if ( HvmSpitOutBluepill () )             // 吐出药丸子
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
    NTSTATUS status;

    KdPrint (("\n[NEWBLUEPILL] DriverEntry~\n"));

    if (VmxIsImplemented ())
    {
        Hvm = &Vmx;
    }
    else
    {
        KdPrint (("DriverEntry(): VMX is not supported!\n"));
        return STATUS_NOT_SUPPORTED;
    }

    status = HvmSwallowBluepill ();          // 吞下药丸子
    if (status)
    {
        KdPrint (("[NEWBLUEPILL] HvmSwallowBluepill() failed with status 0x%08X\n", status));
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    KdPrint (("[NEWBLUEPILL] Initialization finished~\n"));
    return STATUS_SUCCESS;
}
