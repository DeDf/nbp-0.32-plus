/* 
 * Copyright holder: Invisible Things Lab
 */

#include "common.h"
#include "hvm.h"                // FIXME: used only by CmGetPagePaByPageVaCr3() -- maybe we should move it to hvm.c?

NTSTATUS NTAPI CmGetPagePTEAddress (
  PVOID Page,
  PULONG64 * pPagePTE,
  PHYSICAL_ADDRESS * pPA
)
{
  ULONG64 Pml4e, Pdpe, Pde, Pte, PA;
  ULONG64 PageVA = (ULONG64) Page;

  if (!Page || !pPagePTE)
    return STATUS_INVALID_PARAMETER;

  *pPagePTE = NULL;

  Pml4e = *(PULONG64) (((PageVA >> 36) & 0xff8) + PML4_BASE);
  if (!(Pml4e & 1))
    // pml4e not present
    return STATUS_NO_MEMORY;

  Pdpe = *(PULONG64) (((PageVA >> 27) & 0x1ffff8) + PDP_BASE);
  if (!(Pdpe & 1))
    // pdpe not present
    return STATUS_NO_MEMORY;

  Pde = *(PULONG64) (((PageVA >> 18) & 0x3ffffff8) + PD_BASE);
  if (!(Pde & 1))
    // pde not present
    return STATUS_NO_MEMORY;

  if ((Pde & 0x81) == 0x81) {
    // 2-mbyte pde
    PA = ((((PageVA >> 12) & 0x1ff) + ((Pde >> 12) & 0xfffffff)) << 12) + (PageVA & 0xfff);

    if (pPA)
      (*pPA).QuadPart = PA;

    return STATUS_UNSUCCESSFUL;
  }

  Pte = *(PULONG64) (((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);
  if (!(Pte & 1))
    // pte not present
    return STATUS_NO_MEMORY;

  *pPagePTE = (PULONG64) (((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

  PA = (((Pte >> 12) & 0xfffffff) << 12) + (PageVA & 0xfff);
  if (pPA)
    (*pPA).QuadPart = PA;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmPatchPTEPhysicalAddress (
  PULONG64 pPte,
  PVOID PageVA,
  PHYSICAL_ADDRESS NewPhysicalAddress
)
{
  ULONG64 Pte;

  if (!pPte || !PageVA)
    return STATUS_INVALID_PARAMETER;

  Pte = *pPte;
  Pte &= 0xfff0000000000fff;
  Pte |= NewPhysicalAddress.QuadPart & 0xffffffffff000;
  *pPte = Pte;

  CmInvalidatePage (PageVA);

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmDumpGdt (
  PUCHAR GdtBase,
  USHORT GdtLimit
)
{
  PSEGMENT_DESCRIPTOR SegmentDescriptor;
  ULONG Limit, Selector = 0, Type;
  ULONG64 SegBase;
  ULONG32 SegLimit;

  if (!GdtBase)
    return STATUS_INVALID_PARAMETER;

  _KdPrint (("CmDumpGdt(): Dumping GDT at 0x%p\n", GdtBase));

  SegmentDescriptor = (PSEGMENT_DESCRIPTOR) GdtBase;
  while ((PUCHAR) SegmentDescriptor < GdtBase + GdtLimit) {

    // segment base is ignored for DS, ES and SS
    SegBase = SegmentDescriptor->BaseLow | SegmentDescriptor->BaseMid << 16 | SegmentDescriptor->BaseHigh << 24;
    SegLimit = SegmentDescriptor->LimitLow | SegmentDescriptor->LimitHigh << 16;

    if (SegmentDescriptor->AttributesHigh & 0x8)
      // 4096-bit granularity is enabled for this segment, scale the limit
      SegLimit <<= 12;

    if (*((PULONG64) SegmentDescriptor) == 0) {
      _KdPrint (("CmDumpGdt(): 0x%02X: NULL\n", Selector));
    } else if (((SegmentDescriptor->AttributesLow & 0x10))) {
      _KdPrint (("CmDumpGdt(): 0x%02X: %s %02X %01X base 0x%p limit 0x%X\n",
                 Selector,
                 !(SegmentDescriptor->AttributesLow & 8) ? "DATA  " :
                 SegmentDescriptor->AttributesHigh & 0x2 ? "CODE64" : "CODE32",
                 SegmentDescriptor->AttributesLow, SegmentDescriptor->AttributesHigh, SegBase, SegLimit));
    } else {

      Type = SegmentDescriptor->AttributesLow & 0xf;
      SegBase = (*(PULONG64) ((PUCHAR) SegmentDescriptor + 4)) & 0xffffffffff000000;
      SegBase |= (*(PULONG32) ((PUCHAR) SegmentDescriptor + 2)) & 0x00ffffff;

      _KdPrint (("CmDumpGdt(): 0x%02X: %s %02X %01X base 0x%p limit 0x%X\n",
                 Selector,
                 Type == 2 ? "LDT64 " :
                 Type == 9 ? "ATSS64" :
                 Type == 0x0b ? "BTSS64" :
                 Type == 0x0c ? "CALLGATE64" : "*INVALID*",
                 SegmentDescriptor->AttributesLow, SegmentDescriptor->AttributesHigh, SegBase, SegLimit));

      SegmentDescriptor++;
      Selector += 8;
    }

    SegmentDescriptor++;
    Selector += 8;
  }

  return STATUS_SUCCESS;
}

NTSTATUS CmDumpTSS64 (
  PTSS64 Tss64,
  USHORT Tss64Limit
)
{
  if (!Tss64)
    return STATUS_INVALID_PARAMETER;

  _KdPrint (("CmDumpTSS64(): Dumping TSS64 at 0x%p, limit %d\n", Tss64, Tss64Limit));

  _KdPrint (("CmDumpTSS64(): Reserved0: 0x%p\n", Tss64->Reserved0));

  _KdPrint (("CmDumpTSS64(): RSP0: 0x%p\n", Tss64->RSP0));
  _KdPrint (("CmDumpTSS64(): RSP1: 0x%p\n", Tss64->RSP1));
  _KdPrint (("CmDumpTSS64(): RSP2: 0x%p\n", Tss64->RSP2));

  _KdPrint (("CmDumpTSS64(): Reserved1: 0x%p\n", Tss64->Reserved1));

  _KdPrint (("CmDumpTSS64(): IST1: 0x%p\n", Tss64->IST1));
  _KdPrint (("CmDumpTSS64(): IST2: 0x%p\n", Tss64->IST2));
  _KdPrint (("CmDumpTSS64(): IST3: 0x%p\n", Tss64->IST3));
  _KdPrint (("CmDumpTSS64(): IST4: 0x%p\n", Tss64->IST4));
  _KdPrint (("CmDumpTSS64(): IST5: 0x%p\n", Tss64->IST5));
  _KdPrint (("CmDumpTSS64(): IST6: 0x%p\n", Tss64->IST6));
  _KdPrint (("CmDumpTSS64(): IST7: 0x%p\n", Tss64->IST7));
  _KdPrint (("CmDumpTSS64(): IST7: 0x%p\n", Tss64->IST7));

  _KdPrint (("CmDumpTSS64(): Reserved2: 0x%p\n", Tss64->Reserved2));
  _KdPrint (("CmDumpTSS64(): Reserved3: 0x%p\n", Tss64->Reserved3));

  _KdPrint (("CmDumpTSS64(): IOMapBaseAddress: %d\n", Tss64->IOMapBaseAddress));

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmSetGdtEntry (
  PSEGMENT_DESCRIPTOR GdtBase,
  ULONG GdtLimit,
  ULONG SelectorNumber,
  PVOID SegmentBase,
  ULONG SegmentLimit,
  UCHAR LowAttributes,
  UCHAR HighAttributes
)
{
  SEGMENT_DESCRIPTOR Descriptor = { 0 };

  if (!GdtBase || SelectorNumber > GdtLimit || (SelectorNumber & 7))
    return STATUS_INVALID_PARAMETER;

  Descriptor.LimitLow  = (USHORT) (SegmentLimit & 0xffff);
  Descriptor.LimitHigh = (UCHAR) (SegmentLimit >> 16);
  Descriptor.BaseLow  = (USHORT) ((ULONG64) SegmentBase & 0xffff);
  Descriptor.BaseMid  = (UCHAR) (((ULONG64) SegmentBase >> 16) & 0xff);
  Descriptor.BaseHigh = (UCHAR) (((ULONG64) SegmentBase >> 24) & 0xff);
  Descriptor.AttributesLow  = LowAttributes;
  Descriptor.AttributesHigh = HighAttributes;

  GdtBase[SelectorNumber >> 3] = Descriptor;

  if (!(LowAttributes & LA_STANDARD)) {
    // this is a TSS or callgate etc, save the base high part
    *(PULONG64) (((PUCHAR) GdtBase) + SelectorNumber + 8) = ((ULONG64) SegmentBase) >> 32;
  }

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmSetIdtEntry (
  PINTERRUPT_GATE_DESCRIPTOR IdtBase,
  ULONG IdtLimit,
  ULONG InterruptNumber,
  USHORT TargetSelector,
  PVOID TargetOffset,
  UCHAR InterruptStackTable,
  UCHAR Attributes
)
{
  INTERRUPT_GATE_DESCRIPTOR Descriptor = { 0 };

  if (!IdtBase || InterruptNumber * sizeof (INTERRUPT_GATE_DESCRIPTOR) > IdtLimit)
    return STATUS_INVALID_PARAMETER;

  Descriptor.TargetSelector = TargetSelector;
  Descriptor.TargetOffset1500 = (USHORT) ((ULONG64) TargetOffset & 0xffff);
  Descriptor.TargetOffset3116 = (USHORT) (((ULONG64) TargetOffset >> 16) & 0xffff);
  Descriptor.TargetOffset6332 = (ULONG32) (((ULONG64) TargetOffset >> 32) & 0xffffffff);
  Descriptor.InterruptStackTable = InterruptStackTable;
  Descriptor.Attributes = Attributes;

  IdtBase[InterruptNumber] = Descriptor;

  return STATUS_SUCCESS;
}

VOID NTAPI CmFreePhysPages (
  PVOID BaseAddress,
  ULONG uNoOfPages
)
{
  // memory manager collects all used memory
}

NTSTATUS NTAPI CmInitializeSegmentSelector (
  SEGMENT_SELECTOR * SegmentSelector,
  USHORT Selector,
  PUCHAR GdtBase
)
{
  PSEGMENT_DESCRIPTOR SegDesc;

  if (!SegmentSelector)
    return STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    KdPrint (("CmInitializeSegmentSelector(): Given selector (0x%X) points to LDT\n", Selector));
    return STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR) ((PUCHAR) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel   = Selector;
  SegmentSelector->base  = SegDesc->BaseLow | SegDesc->BaseMid << 16 | SegDesc->BaseHigh << 24;
  SegmentSelector->limit = SegDesc->LimitLow | SegDesc->LimitHigh << 16;
  SegmentSelector->attributes = SegDesc->AttributesLow | SegDesc->AttributesHigh << 8;

  if (!(SegDesc->AttributesLow & LA_STANDARD)) {
    // this is a TSS or callgate etc, save the base high part
    SegmentSelector->base |= (*(PULONG64) ((PUCHAR) SegDesc + 8)) << 32;
  }

#define IS_GRANULARITY_4KB  (1 << 0xB)

  if ( SegmentSelector->attributes & IS_GRANULARITY_4KB ) {
    // 4096-bit granularity is enabled for this segment, scale the limit
    SegmentSelector->limit = (SegmentSelector->limit << 12) | 0xfff;
  }

  return STATUS_SUCCESS;
}

#ifdef _X86_
NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[1], &Value, 4);
    uCodeLength = 5;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[1], &Value, 4);
    uCodeLength = 5;
    break;

  case REG_CONTROL:
    uCodeLength = *pGeneratedCodeLength;
    CmGenerateMovReg (pCode, pGeneratedCodeLength, REG_RAX, Value);
    // calc the size of the "mov rax, value"
    uCodeLength = *pGeneratedCodeLength - uCodeLength;
    pCode += uCodeLength;

    // mov crX, rax

    pCode[0] = 0x0f;
    pCode[1] = 0x22;
    pCode[2] = 0xc0 | (UCHAR) ((Register & REG_MASK) << 3);

    // *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
    uCodeLength = 3;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}
#else
NTSTATUS NTAPI CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0x48;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x49;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_CONTROL:
    uCodeLength = *pGeneratedCodeLength;
    CmGenerateMovReg (pCode, pGeneratedCodeLength, REG_RAX, Value);
    // calc the size of the "mov rax, value"
    uCodeLength = *pGeneratedCodeLength - uCodeLength;
    pCode += uCodeLength;

    uCodeLength = 0;

    if (Register == (REG_CR8)) {
      // build 0x44 0x0f 0x22 0xc0
      pCode[0] = 0x44;
      uCodeLength = 1;
      pCode++;
      Register = 0;
    }
    // mov crX, rax

    pCode[0] = 0x0f;
    pCode[1] = 0x22;
    pCode[2] = 0xc0 | (UCHAR) ((Register & REG_MASK) << 3);

    // *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
    uCodeLength += 3;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}
#endif

NTSTATUS NTAPI CmGenerateCallReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 2;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x41;
    pCode[1] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 3;
    break;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}

NTSTATUS NTAPI CmGeneratePushReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  if ((Register & ~REG_MASK) != REG_GP)
    return STATUS_NOT_SUPPORTED;

  pCode[0] = 0x50 | (UCHAR) (Register & REG_MASK);
  *pGeneratedCodeLength += 1;

  return STATUS_SUCCESS;
}

#ifdef _X86_
NTSTATUS NTAPI CmGenerateIretd (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  pCode[0] = 0xcf;
  *pGeneratedCodeLength += 1;

  return STATUS_SUCCESS;
}
#else
NTSTATUS NTAPI CmGenerateIretq (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  pCode[0] = 0x48;
  pCode[1] = 0xcf;
  *pGeneratedCodeLength += 2;

  return STATUS_SUCCESS;
}
#endif

BOOLEAN CmIsBitSet (
  ULONG64 v,
  UCHAR bitNo
)
{
  ULONG64 mask = (ULONG64) 1 << bitNo;

  return (BOOLEAN) ((v & mask) != 0);
}

ULONG64 CmBitSetByValue (
  ULONG64 v,
  UCHAR bitNo,
  BOOLEAN Value
)
{
  if (Value)
    v |= ((ULONG64) 1 << bitNo);
  else
    v &= ~((ULONG64) 1 << bitNo);
  return v;
}

VOID CmPageBitAdd (
  PVOID Target,
  PVOID Source1,
  PVOID Source2
)                               //target=source1|source2
{
  int i;
  for (i = 0; i < (PAGE_SIZE / sizeof (ULONG64)); i++)  //4k
  {
    *((PULONG64) Target + i) = *((PULONG64) Source1 + i) | *((PULONG64) Source2 + i);
  }

}
