	segment .text
	BITS 64
	global compareCharacters

compareCharacters:
	push rbp
	mov rbp, rsp
	sub rsp, 8
	cmp rdi, rsi
	je same
	mov rax, 0
	jmp end
same:	mov rax, 1
end:	mov rsp, rbp
	pop rbp
	ret
	