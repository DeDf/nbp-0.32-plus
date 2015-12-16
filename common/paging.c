/* 
 * Copyright holder: Invisible Things Lab
 * 
 * This software is protected by domestic and International
 * copyright laws. Any use (including publishing and
 * distribution) of this software requires a valid license
 * from the copyright holder.
 *
 * This software is provided for the educational use only
 * during the Black Hat training. This software should not
 * be used on production systems.
 *
 */

#include "paging.h"

#define DbgPrint(...) {}

PVOID NTAPI MmAllocatePages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
)
{
  PVOID PageVA;
  PHYSICAL_ADDRESS PagePA;

  if (!uNumberOfPages)
    return NULL;

  PageVA = ExAllocatePoolWithTag (NonPagedPool, uNumberOfPages * PAGE_SIZE, ITL_TAG);
  if (!PageVA)
    return NULL;
  RtlZeroMemory (PageVA, uNumberOfPages * PAGE_SIZE);

  if (pFirstPagePA)
    *pFirstPagePA = MmGetPhysicalAddress (PageVA);

  return PageVA;
}

PVOID NTAPI MmAllocateContiguousPages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
)
{
  return MmAllocateContiguousPagesSpecifyCache(uNumberOfPages,pFirstPagePA, MmCached);
}

PVOID NTAPI MmAllocateContiguousPagesSpecifyCache (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA,
  ULONG CacheType
)
{
  PVOID PageVA;
  PHYSICAL_ADDRESS PagePA, l1, l2, l3;

  if (!uNumberOfPages)
    return NULL;

  l1.QuadPart = 0;
  l2.QuadPart = -1;
  l3.QuadPart = 0x10000;

  PageVA = MmAllocateContiguousMemorySpecifyCache (uNumberOfPages * PAGE_SIZE, l1, l2, l3, CacheType);
  if (!PageVA)
    return NULL;

  RtlZeroMemory (PageVA, uNumberOfPages * PAGE_SIZE);

  PagePA = MmGetPhysicalAddress (PageVA);
  if (pFirstPagePA)
    *pFirstPagePA = PagePA;

  return PageVA;
}
