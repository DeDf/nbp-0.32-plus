; 
; Copyright holder: Invisible Things Lab
;

EXTERN	 VmExitHandler:PROC

HVM_SAVE_ALL_NOSEGREGS MACRO
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8        
        push rdi
        push rsi
        push rbp
        push rbp	; rsp
        push rbx
        push rdx
        push rcx
        push rax
ENDM

HVM_RESTORE_ALL_NOSEGREGS MACRO
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp		; rsp
        pop rbp
        pop rsi
        pop rdi 
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
ENDM

.CODE

set_in_cr4 PROC 
	mov rax,cr4
	or  rcx,rax
	mov cr4,rcx
	ret
set_in_cr4 ENDP

clear_in_cr4 PROC 
	mov rax,cr4
	not rcx
	and rcx,rax
	mov cr4,rcx
	ret
clear_in_cr4 ENDP


VmxRead PROC
	vmread rax, rcx
	ret
VmxRead ENDP

VmxVmCall PROC
	vmcall
	ret
VmxVmCall ENDP


; Stack layout for vmxLaunch() call:
;
; ^                              ^
; |                              |
; | lots of pages for host stack |
; |                              |
; |------------------------------|   <- HostStackBottom(rcx) points here
; |         struct CPU           |
; --------------------------------

;====== VmxVMexitHandler ======

VmxVmexitHandler PROC   

	HVM_SAVE_ALL_NOSEGREGS
	
	mov     rcx, [rsp + 80h] ;PCPU
	mov 	rdx, rsp		 ;GuestRegs
	
	sub	rsp, 28h
	call	VmExitHandler
	add	rsp, 28h
	
	HVM_RESTORE_ALL_NOSEGREGS	
	vmresume
	ret

VmxVmexitHandler ENDP

END
