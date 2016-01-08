#include <stdio.h>

int main()
{
    unsigned long  ddeax,ddebx,ddecx,ddedx;

    _asm
    {
        mov  eax, 0xbabecafe
        cpuid 
        mov  ddeax, eax
        mov  ddebx, ebx
        mov  ddecx, ecx
        mov  ddedx, edx
    }

    printf("---- cpuid ----\n");

    printf("eax == %08X \n" ,ddeax);
    printf("ebx == %08X \n" ,ddebx);
    printf("ecx == %08X \n" ,ddecx);
    printf("edx == %08X \n" ,ddedx);
    getchar();
    return 0;
}

