≠	.intel_syntax noprefix
	.text

	xor ecx,ecx /* access mode option */

	xor edx,edx /* counter */

next_page:
	or dx, 0xfff /* Add PAGE_SIZE-1 */

scan_it:
	inc edx

	/* int access(const char *pathname, int mode); */
	lea ebx,[edx+4]
	mov eax, 0x21
	int 0x80

	/*  check the returned errors */
	cmp al,0xf2
	jz short next_page /* access violation in this page*/

	/* Look for the egg */
	mov ebx,0x50505050    	/* the egg: "PPPP" */
	cmp [edx],ebx
	jnz short scan_it

	/* Found it */
	
	/* ssize_t write(int fd, const void *buf, size_t count); */
	mov eax, 4       	/* syscall write */
	mov ebx, 1       	/* stdout is 1 */
	mov ecx,edx 		/* Address of string */
	mov edx, 50      	/* length of the string */
	int 0x80

	
