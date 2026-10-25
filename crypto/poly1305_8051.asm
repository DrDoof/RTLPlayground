	.module poly1305_8051
	.optsdcc -mmcs51 --model-small

	.globl _poly_mul_reduce
	.globl _poly_block_hi
	.globl _poly_block_lo

	.area BANK4 (CODE)

_poly_block_lo:
	mov	r3,#0
	sjmp	pb
_poly_block_hi:
	mov	r3,#1
pb:
	mov	r1,#0xa0
	mov	r2,#16
	clr	c
pb_lp:
	movx	a,@dptr
	inc	dptr
	mov	r7,a
	mov	r6,dpl
	mov	r5,dph
	mov	dph,#0xbe
	mov	dpl,r1
	movx	a,@dptr
	addc	a,r7
	movx	@dptr,a
	mov	dpl,r6
	mov	dph,r5
	inc	r1
	djnz	r2,pb_lp
	mov	dph,#0xbe
	mov	dpl,#0xb0
	movx	a,@dptr
	addc	a,r3
	movx	@dptr,a

_poly_mul_reduce:
	mov	dph,#0xbe
	clr	a
	mov	r5,a
	mov	r6,a
	mov	r7,a
	mov	r2,a
pm_col:
	mov	a,r2
	clr	c
	subb	a,#16
	jc	pm_low
	mov	a,r2
	add	a,#0x91
	mov	r0,a
	mov	r1,#0xc0
	mov	a,#32
	clr	c
	subb	a,r2
	mov	r4,a
	sjmp	pm_in
pm_low:
	mov	r0,#0xa0
	mov	a,r2
	add	a,#0xb1
	mov	r1,a
	mov	a,r2
	inc	a
	mov	r4,a
pm_in:
	mov	dpl,r0
	movx	a,@dptr
	mov	b,a
	mov	dpl,r1
	movx	a,@dptr
	mul	ab
	add	a,r5
	mov	r5,a
	mov	a,b
	addc	a,r6
	mov	r6,a
	jnc	pm_nc
	inc	r7
pm_nc:
	inc	r0
	dec	r1
	djnz	r4,pm_in
	mov	a,r2
	add	a,#0xc1
	mov	dpl,a
	mov	a,r5
	movx	@dptr,a
	mov	a,r6
	mov	r5,a
	mov	a,r7
	mov	r6,a
	mov	r7,#0
	inc	r2
	cjne	r2,#32,pm_col
	mov	dpl,#0xe1
	mov	a,r5
	movx	@dptr,a

	mov	r0,#0xc1
	mov	r1,#0xa0
	mov	r2,#16
	mov	r3,#0
pr_lp:
	mov	a,r0
	add	a,#17
	mov	dpl,a
	movx	a,@dptr
	rr	a
	rr	a
	anl	a,#0xc0
	mov	r4,a
	mov	a,r0
	add	a,#16
	mov	dpl,a
	movx	a,@dptr
	mov	r5,a
	rr	a
	rr	a
	anl	a,#0x3f
	orl	a,r4
	mov	r4,a
	cjne	r2,#16,pr_nf
	mov	a,r5
	anl	a,#0xfc
	mov	r5,a
pr_nf:
	mov	r6,#0
	mov	dpl,r0
	movx	a,@dptr
	add	a,r3
	jnc	pr_c1
	inc	r6
pr_c1:
	add	a,r5
	jnc	pr_c2
	inc	r6
pr_c2:
	add	a,r4
	jnc	pr_c3
	inc	r6
pr_c3:
	mov	dpl,r1
	movx	@dptr,a
	mov	a,r6
	mov	r3,a
	inc	r0
	inc	r1
	djnz	r2,pr_lp
	mov	dpl,#0xd1
	movx	a,@dptr
	anl	a,#3
	add	a,r3
	mov	dpl,#0xb0
	movx	@dptr,a
	ret
