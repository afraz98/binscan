# binscan

## Description

`binscan` is a command-line application used for analyzing ELF-64 binaries. A variety of different aspects of
an ELF-64 object file are printed, including

1) The `SHA-1` checksum of the `.text` section of the binary
2) All unique `x86` instructions utilized in the binary and the frequency of their use 
3) The [Renyi Entropy](https://en.wikipedia.org/wiki/R%C3%A9nyi_entropy) of the ELF-64 object's `.text` section
4) The `SHA-256` checksum of the binary's `.text` section

An analysis result binary file is also created under the same name of the ELF-64 binary analyzed with the `.bin` file extension. The user may later open these bin files with the `--open` option.

## Installation

1) Install the `OpenSSL` and `Capstone` C packages with the following:

``` sudo apt install libcapstone-dev libelf-dev ```

2) Clone this repository.
3) Use the `make` command in the main repository directory.

## Usage

### Binary Analysis 

For binary analysis, `binscan` should be called from the command-line with the following arguments:

``` 
binscan --analyze <binary file name> 
```

Note: The binary file MUST be a valid ELF-64 object for the `binscan` utility to function properly.

### Analysis Examination

To access analysis files, use the `binscan` utility with the following arguments:

```
binscan --open <analysis file name>.bin
```

### Analysis File Encryption

The `binscan` utility supports both encryption and decryption of analysis files. For encryption, the user should input the following:

```
binscan --encrypt <desired binary to be encrypted>.bin <output file name>.bin
```

Similarly, for decryption:

```
binscan --decrypt <desired binary to be decrypted>.bin <output file name>.bin
```


### Sample output

Running `binscan` on `test_executables/sample_exe64.elf`:

```
binscan --analyze sample_exe64.elf

SHA1: 05aa7489b8390300a58540179f6a203d980f6d14

.text
Section starts at 0x400400
Section length: 0x1f8

0x400400:	xor		ebp, ebp
0x400402:	mov		r9, rdx
0x400405:	pop		rsi
0x400406:	mov		rdx, rsp
0x400409:	and		rsp, 0xfffffffffffffff0
0x40040d:	push		rax
0x40040e:	push		rsp
0x40040f:	mov		r8, 0x400520
0x400416:	mov		rcx, 0x400530
0x40041d:	mov		rdi, 0x4004ec
0x400424:	call		0x4003e8
0x400429:	hlt		
0x40042a:	nop		
0x40042b:	nop		
0x40042c:	sub		rsp, 8
0x400430:	mov		rax, qword ptr [rip + 0x200ba9]
0x400437:	test		rax, rax
0x40043a:	je		0x40043e
0x40043c:	call		rax
0x40043e:	add		rsp, 8
0x400442:	ret		
0x400443:	nop		
0x400444:	nop		
0x400445:	nop		
0x400446:	nop		
0x400447:	nop		
0x400448:	nop		
0x400449:	nop		
0x40044a:	nop		
0x40044b:	nop		
0x40044c:	nop		
0x40044d:	nop		
0x40044e:	nop		
0x40044f:	nop		
0x400450:	push		rbp
0x400451:	mov		rbp, rsp
0x400454:	push		rbx
0x400455:	sub		rsp, 8
0x400459:	cmp		byte ptr [rip + 0x200bc0], 0
0x400460:	jne		0x4004ad
0x400462:	mov		eax, 0x600e30
0x400467:	mov		rdx, qword ptr [rip + 0x200bba]
0x40046e:	sub		rax, 0x600e28
0x400474:	sar		rax, 3
0x400478:	lea		rbx, qword ptr [rax - 1]
0x40047c:	cmp		rdx, rbx
0x40047f:	jae		0x4004a6
0x400481:	nop		dword ptr [rax]
0x400488:	lea		rax, qword ptr [rdx + 1]
0x40048c:	mov		qword ptr [rip + 0x200b95], rax
0x400493:	call		qword ptr [rax*8 + 0x600e28]
0x40049a:	mov		rdx, qword ptr [rip + 0x200b87]
0x4004a1:	cmp		rdx, rbx
0x4004a4:	jb		0x400488
0x4004a6:	mov		byte ptr [rip + 0x200b73], 1
0x4004ad:	add		rsp, 8
0x4004b1:	pop		rbx
0x4004b2:	leave		
0x4004b3:	ret		
0x4004b4:	nop		word ptr cs:[rax + rax]
0x4004c0:	push		rbp
0x4004c1:	cmp		qword ptr [rip + 0x20096f], 0
0x4004c9:	mov		rbp, rsp
0x4004cc:	je		0x4004e8
0x4004ce:	mov		eax, 0
0x4004d3:	test		rax, rax
0x4004d6:	je		0x4004e8
0x4004d8:	mov		edi, 0x600e38
0x4004dd:	mov		r11, rax
0x4004e0:	leave		
0x4004e1:	jmp		r11
0x4004e4:	nop		dword ptr [rax]
0x4004e8:	leave		
0x4004e9:	ret		
0x4004ea:	nop		
0x4004eb:	nop		
0x4004ec:	push		rbp
0x4004ed:	mov		rbp, rsp
0x4004f0:	mov		dword ptr [rbp - 4], edi
0x4004f3:	mov		qword ptr [rbp - 0x10], rsi
0x4004f7:	mov		rax, qword ptr [rbp - 0x10]
0x4004fb:	mov		edx, eax
0x4004fd:	mov		eax, dword ptr [rip + 0x200b15]
0x400503:	lea		eax, dword ptr [rdx + rax]
0x400506:	mov		dword ptr [rip + 0x200b0c], eax
0x40050c:	mov		eax, dword ptr [rip + 0x200b06]
0x400512:	add		eax, dword ptr [rbp - 4]
0x400515:	leave		
0x400516:	ret		
0x400517:	nop		
0x400518:	nop		
0x400519:	nop		
0x40051a:	nop		
0x40051b:	nop		
0x40051c:	nop		
0x40051d:	nop		
0x40051e:	nop		
0x40051f:	nop		
0x400520:	ret		
0x400522:	nop		word ptr cs:[rax + rax]
0x400530:	mov		qword ptr [rsp - 0x28], rbp
0x400535:	mov		qword ptr [rsp - 8], r15
0x40053a:	lea		rbp, qword ptr [rip + 0x2008d3]
0x400541:	lea		r15, qword ptr [rip + 0x2008cc]
0x400548:	mov		qword ptr [rsp - 0x20], r12
0x40054d:	mov		qword ptr [rsp - 0x18], r13
0x400552:	mov		qword ptr [rsp - 0x10], r14
0x400557:	mov		qword ptr [rsp - 0x30], rbx
0x40055c:	sub		rsp, 0x38
0x400560:	sub		rbp, r15
0x400563:	mov		r14d, edi
0x400566:	mov		r13, rsi
0x400569:	sar		rbp, 3
0x40056d:	mov		r12, rdx
0x400570:	call		0x4003c0
0x400575:	test		rbp, rbp
0x400578:	je		0x400596
0x40057a:	xor		ebx, ebx
0x40057c:	nop		dword ptr [rax]
0x400580:	mov		rdx, r12
0x400583:	mov		rsi, r13
0x400586:	mov		edi, r14d
0x400589:	call		qword ptr [r15 + rbx*8]
0x40058d:	add		rbx, 1
0x400591:	cmp		rbx, rbp
0x400594:	jb		0x400580
0x400596:	mov		rbx, qword ptr [rsp + 8]
0x40059b:	mov		rbp, qword ptr [rsp + 0x10]
0x4005a0:	mov		r12, qword ptr [rsp + 0x18]
0x4005a5:	mov		r13, qword ptr [rsp + 0x20]
0x4005aa:	mov		r14, qword ptr [rsp + 0x28]
0x4005af:	mov		r15, qword ptr [rsp + 0x30]
0x4005b4:	add		rsp, 0x38
0x4005b8:	ret		
0x4005b9:	nop		
0x4005ba:	nop		
0x4005bb:	nop		
0x4005bc:	nop		
0x4005bd:	nop		
0x4005be:	nop		
0x4005bf:	nop		
0x4005c0:	push		rbp
0x4005c1:	mov		rbp, rsp
0x4005c4:	push		rbx
0x4005c5:	sub		rsp, 8
0x4005c9:	mov		rax, qword ptr [rip + 0x200848]
0x4005d0:	cmp		rax, -1
0x4005d4:	je		0x4005ef
0x4005d6:	mov		ebx, 0x600e18
0x4005db:	nop		dword ptr [rax + rax]
0x4005e0:	sub		rbx, 8
0x4005e4:	call		rax
0x4005e6:	mov		rax, qword ptr [rbx]
0x4005e9:	cmp		rax, -1
0x4005ed:	jne		0x4005e0
0x4005ef:	add		rsp, 8
0x4005f3:	pop		rbx
0x4005f4:	leave		
0x4005f5:	ret		
0x4005f6:	nop		
0x4005f7:	nop		

xor	2
mov	46
pop	3
and	1
push	8
call	6
hlt	1
nop	41
sub	7
test	3
je	5
add	6
ret	7
cmp	7
jne	2
sar	2
lea	5
jae	1
jb	2
leave	5
jmp	1

504 bytes in section .text
Renyi Entropy: 0.181157
SHA256: 5836ed6ff8f9057666f469b96dd6e3992c8026767755223380bc48053882f9d6
Saving analysis to test_executables/sample_exe64.elf.bin ..

```