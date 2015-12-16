#pragma once

#include <ntddk.h>
#include "common.h"

#define KBD_STATE_IO_PORT     0x60
#define KBD_DATA_IO_PORT      0x64

#define I8042_IN_BUFFER_FULL  0x02