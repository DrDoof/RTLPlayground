	.module fe_mul_8051
	.optsdcc -mmcs51 --model-small

	.globl _fe_mul_core
	.globl _fe_sq_core
	.globl _fe_load_a
	.globl _fe_load_b
	.globl _fe_store
	.globl _fe_store_a
	.globl _fe_reduce_a

ar3 = 0x03
ar4 = 0x04

	.area BANK4 (CODE)

_fe_mul_core:
	mov	a,sp
	add	a,#104
	jnc	fmi_go
	ljmp	fmc_xdata
fmi_go:
	mov	a,sp
	inc	a
	mov	r3,a
	add	a,#63
	mov	sp,a
	mov	dptr,#0xbe00
	mov	a,r3
	mov	r0,a
	mov	r2,#64
fmi_cp:
	movx	a,@dptr
	mov	@r0,a
	inc	dptr
	inc	r0
	djnz	r2,fmi_cp
	mov	dph,#0xbe
	clr	a
	mov	r5,a
	mov	r6,a
	mov	r7,a
	mov	r2,a
fmi_col:
	mov	a,r2
	clr	c
	subb	a,#32
	jc	fmi_low
	mov	a,r2
	add	a,#0xe1
	add	a,r3
	mov	r0,a
	mov	a,r3
	add	a,#63
	mov	r1,a
	mov	a,#63
	clr	c
	subb	a,r2
	mov	r4,a
	sjmp	fmi_in
fmi_low:
	mov	a,r3
	mov	r0,a
	add	a,#32
	add	a,r2
	mov	r1,a
	mov	a,r2
	inc	a
	mov	r4,a
fmi_in:
	mov	a,@r0
	mov	b,@r1
	mul	ab
	add	a,r5
	mov	r5,a
	mov	a,b
	addc	a,r6
	mov	r6,a
	jnc	fmi_nc
	inc	r7
fmi_nc:
	inc	r0
	dec	r1
	djnz	r4,fmi_in
	mov	a,r2
	add	a,#0x40
	mov	dpl,a
	mov	a,r5
	movx	@dptr,a
	mov	a,r6
	mov	r5,a
	mov	a,r7
	mov	r6,a
	mov	r7,#0
	inc	r2
	cjne	r2,#63,fmi_col
	mov	dpl,#0x7f
	mov	a,r5
	movx	@dptr,a
	mov	a,r3
	dec	a
	mov	sp,a
	ret

_fe_sq_core:
	mov	a,sp
	add	a,#72
	jnc	fsi_go
	ljmp	fsq_xdata
fsi_go:
	mov	a,sp
	inc	a
	mov	r3,a
	add	a,#31
	mov	sp,a
	mov	dptr,#0xbe00
	mov	a,r3
	mov	r0,a
	mov	r2,#32
fsi_cp:
	movx	a,@dptr
	mov	@r0,a
	inc	dptr
	inc	r0
	djnz	r2,fsi_cp
	mov	dptr,#0xbe40
	clr	a
	movx	@dptr,a
	inc	dptr
	movx	@dptr,a
	mov	r2,a
fsi_col:
	mov	a,r2
	clr	c
	subb	a,#32
	jc	fsi_low
	mov	a,r2
	add	a,#0xe1
	sjmp	fsi_have
fsi_low:
	clr	a
fsi_have:
	mov	r4,a
	add	a,r3
	mov	r0,a
	mov	a,r2
	clr	c
	subb	a,r4
	add	a,r3
	mov	r1,a
	mov	a,r2
	inc	a
	clr	c
	rrc	a
	clr	c
	subb	a,r4
	mov	r4,a
	clr	a
	mov	r5,a
	mov	r6,a
	mov	r7,a
	mov	a,r4
	jz	fsi_nop
fsi_in:
	mov	a,@r0
	mov	b,@r1
	mul	ab
	add	a,r5
	mov	r5,a
	mov	a,b
	addc	a,r6
	mov	r6,a
	jnc	fsi_nc
	inc	r7
fsi_nc:
	inc	r0
	dec	r1
	djnz	r4,fsi_in
	mov	a,r5
	add	a,r5
	mov	r5,a
	mov	a,r6
	rlc	a
	mov	r6,a
	mov	a,r7
	rlc	a
	mov	r7,a
fsi_nop:
	mov	a,r2
	jb	acc.0,fsi_nd
	rr	a
	add	a,r3
	mov	r0,a
	mov	a,@r0
	mov	b,a
	mul	ab
	add	a,r5
	mov	r5,a
	mov	a,b
	addc	a,r6
	mov	r6,a
	clr	a
	addc	a,r7
	mov	r7,a
fsi_nd:
	mov	a,r2
	add	a,#0x40
	mov	dpl,a
	movx	a,@dptr
	add	a,r5
	mov	r5,a
	inc	dptr
	movx	a,@dptr
	addc	a,r6
	mov	r6,a
	clr	a
	addc	a,r7
	mov	r7,a
	mov	a,r6
	movx	@dptr,a
	inc	dptr
	mov	a,r7
	movx	@dptr,a
	mov	a,r2
	add	a,#0x40
	mov	dpl,a
	mov	a,r5
	movx	@dptr,a
	inc	r2
	cjne	r2,#63,fsi_col
	mov	a,r3
	dec	a
	mov	sp,a
	ret

fmc_xdata:
	mov	dptr,#0xbeff
	movx	a,@dptr
	inc	a
	jz	fmc_sat
	movx	@dptr,a
fmc_sat:
	mov	dph,#0xbe
	clr	a
	mov	r5,a
	mov	r6,a
	mov	r7,a
	mov	r2,a
fmc_col:
	mov	a,r2
	clr	c
	subb	a,#32
	jc	fmc_low
	mov	a,r2
	add	a,#0xe1
	mov	r0,a
	mov	r1,#0x3f
	mov	a,#63
	clr	c
	subb	a,r2
	mov	r4,a
	sjmp	fmc_inner
fmc_low:
	mov	r0,#0x00
	mov	a,r2
	add	a,#0x20
	mov	r1,a
	mov	a,r2
	inc	a
	mov	r4,a
fmc_inner:
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
	jnc	fmc_nc
	inc	r7
fmc_nc:
	inc	r0
	dec	r1
	djnz	r4,fmc_inner
	mov	a,r2
	add	a,#0x40
	mov	dpl,a
	mov	a,r5
	movx	@dptr,a
	mov	a,r6
	mov	r5,a
	mov	a,r7
	mov	r6,a
	mov	r7,#0
	inc	r2
	cjne	r2,#63,fmc_col
	mov	dpl,#0x7f
	mov	a,r5
	movx	@dptr,a
	ret

fsq_xdata:
	mov	dptr,#0xbeff
	movx	a,@dptr
	inc	a
	jz	fsq_sat
	movx	@dptr,a
fsq_sat:
	mov	dph,#0xbe
	clr	a
	mov	r2,a
	mov	r3,a
	mov	r4,a
fsq_col:
	mov	a,r2
	clr	c
	subb	a,#32
	jc	fsq_low
	mov	a,r2
	add	a,#0xe1
	sjmp	fsq_have
fsq_low:
	clr	a
fsq_have:
	mov	r0,a
	mov	a,r2
	clr	c
	subb	a,r0
	mov	r1,a
	push	ar3
	push	ar4
	mov	a,r2
	inc	a
	clr	c
	rrc	a
	clr	c
	subb	a,r0
	mov	r4,a
	clr	a
	mov	r5,a
	mov	r6,a
	mov	r7,a
	mov	a,r4
	jz	fsq_nopairs
fsq_inner:
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
	jnc	fsq_nc
	inc	r7
fsq_nc:
	inc	r0
	dec	r1
	djnz	r4,fsq_inner
	mov	a,r5
	add	a,r5
	mov	r5,a
	mov	a,r6
	rlc	a
	mov	r6,a
	mov	a,r7
	rlc	a
	mov	r7,a
fsq_nopairs:
	pop	ar4
	pop	ar3
	mov	a,r2
	jb	acc.0,fsq_nodiag
	rr	a
	mov	dpl,a
	movx	a,@dptr
	mov	b,a
	mul	ab
	add	a,r5
	mov	r5,a
	mov	a,b
	addc	a,r6
	mov	r6,a
	clr	a
	addc	a,r7
	mov	r7,a
fsq_nodiag:
	mov	a,r5
	add	a,r3
	mov	r5,a
	mov	a,r6
	addc	a,r4
	mov	r6,a
	clr	a
	addc	a,r7
	mov	r7,a
	mov	a,r2
	add	a,#0x40
	mov	dpl,a
	mov	a,r5
	movx	@dptr,a
	mov	a,r6
	mov	r3,a
	mov	a,r7
	mov	r4,a
	inc	r2
	cjne	r2,#63,fsq_col
	mov	dpl,#0x7f
	mov	a,r3
	movx	@dptr,a
	ret

_fe_load_b:
	mov	r1,#0x20
	sjmp	fld
_fe_load_a:
	mov	r1,#0x00
fld:
	mov	r2,#32
fld_lp:
	movx	a,@dptr
	inc	dptr
	mov	r6,dpl
	mov	r7,dph
	mov	dph,#0xbe
	mov	dpl,r1
	movx	@dptr,a
	mov	dpl,r6
	mov	dph,r7
	inc	r1
	djnz	r2,fld_lp
	ret

fe_reduce_core:
	mov	dph,#0xbe
	mov	r0,#0x40
	mov	r1,#0x80
	mov	r3,#0
	mov	r2,#32
frc_lp:
	mov	a,r0
	add	a,#32
	mov	dpl,a
	movx	a,@dptr
	mov	b,#38
	mul	ab
	add	a,r3
	mov	r4,a
	clr	a
	addc	a,b
	mov	r5,a
	mov	dpl,r0
	movx	a,@dptr
	add	a,r4
	mov	dpl,r1
	movx	@dptr,a
	clr	a
	addc	a,r5
	mov	r3,a
	inc	r0
	inc	r1
	djnz	r2,frc_lp
frc_fold:
	mov	a,r3
	jz	frc_done
	mov	b,#38
	mul	ab
	mov	r4,a
	mov	r5,b
	mov	r1,#0x80
	mov	r2,#32
frc_f2:
	mov	dpl,r1
	movx	a,@dptr
	add	a,r4
	movx	@dptr,a
	mov	a,r5
	addc	a,#0
	mov	r4,a
	mov	r5,#0
	jz	frc_done
	inc	r1
	djnz	r2,frc_f2
	mov	a,r4
	mov	r3,a
	sjmp	frc_fold
frc_done:
	ret

_fe_store:
	mov	r6,dpl
	mov	r7,dph
	lcall	fe_reduce_core
	mov	r1,#0x80
	sjmp	fst
_fe_store_a:
	mov	r6,dpl
	mov	r7,dph
	mov	r1,#0x00
fst:
	mov	r2,#32
fst_lp:
	mov	dph,#0xbe
	mov	dpl,r1
	movx	a,@dptr
	mov	dpl,r6
	mov	dph,r7
	movx	@dptr,a
	inc	dptr
	mov	r6,dpl
	mov	r7,dph
	inc	r1
	djnz	r2,fst_lp
	ret

_fe_reduce_a:
	lcall	fe_reduce_core
	mov	r1,#0x80
	mov	r0,#0x00
	mov	r2,#32
fra_lp:
	mov	dpl,r1
	movx	a,@dptr
	mov	dpl,r0
	movx	@dptr,a
	inc	r0
	inc	r1
	djnz	r2,fra_lp
	ret
