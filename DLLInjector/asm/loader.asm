BITS 64
.text
global _start

_start
	push rax
	push rdx
	push rcx
	mov rcx,0x1122334455667788
	mov rax,0x2122232425262728
	call rax
	pop rcx
	pop rdx
	pop rax
	mov rax,0x3132333435363738
	jmp rax