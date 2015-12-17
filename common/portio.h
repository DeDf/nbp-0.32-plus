/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "regs.h"

#define LS_THR_EMPTY	0x20

#define TRANSMIT_HOLDING_REGISTER	0x00
#define LINE_STATUS_REGISTER		0x05

UCHAR g_BpId;

VOID NTAPI PioInit (
  PUCHAR ComPortAddress
);

VOID NTAPI PioOutByte (
  UCHAR Byte
);
