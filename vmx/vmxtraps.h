/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "traps.h"
#include "hypercalls.h"

NTSTATUS NTAPI VmxRegisterTraps (
  PCPU Cpu
);
