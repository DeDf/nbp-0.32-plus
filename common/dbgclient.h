/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "dbgclient_ioctl.h"

NTSTATUS NTAPI DbgRegisterWindow (
  UCHAR bBpId
);
NTSTATUS NTAPI DbgUnregisterWindow (
);
VOID NTAPI DbgPrintString (
  PUCHAR pString
);
