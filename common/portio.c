/* 
 * Copyright holder: Invisible Things Lab
 */

#include "portio.h"

// Bug: doesn't initialize port

static PUCHAR g_DebugComPort = NULL;
static UCHAR bDummy;

VOID NTAPI PioInit (
  PUCHAR ComPortAddress
)
{
  g_DebugComPort = ComPortAddress;
}

VOID NTAPI PioOutByte (
  UCHAR Byte
)
{
  ULONG i;

  while (!(READ_PORT_UCHAR (g_DebugComPort + LINE_STATUS_REGISTER) & LS_THR_EMPTY)) {
    bDummy ^= 1;
  };
  WRITE_PORT_UCHAR (g_DebugComPort + TRANSMIT_HOLDING_REGISTER, Byte);
}
