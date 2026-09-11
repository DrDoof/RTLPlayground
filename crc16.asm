;
; CRC16 calculation module
;
	.globl 	_crc_value
	.globl 	_crc16
	.globl 	_crc16_bank1
	.globl 	_crc16_copy
	.globl 	_crc16_init
	.globl 	_crc_ptr_h
	.globl 	_crc_ptr_l
	.globl 	_crc_dst_h
	.globl 	_crc_dst_l
	.globl 	_crc_cnt
	.globl 	__sdcc_banked_ret
;	.equ	DPS, 0x86
; Variable in XMEM holding current CRC16 value, being updated
	.area XSEG    (XDATA)
_crc_value::
	.ds 2
_crc_ptr_h::
	.ds 1
_crc_ptr_l::
	.ds 1
_crc_dst_h::
	.ds 1
_crc_dst_l::
	.ds 1
_crc_cnt::
	.ds 1
; 256 low bytes followed by 256 high bytes of the table, filled by crc16_init
crc16_tab:
	.ds 512

;-------------------------------------------------------
; CRC16 subroutine
; - dptr points to byte to be CRCd in xmem
; - algorithm uses table lookup
;-------------------------------------------------------
	.area HOME    (CODE)
	.area CSEG    (CODE)
_crc16_bank1:
	push	dph
	push	dpl
	movx	a, @dptr
	mov	b, a
	mov	dptr, #_crc_value
	movx	a, @dptr
	xrl	a, b
	add	a, #crc16_tab
	push	a
	clr	a
	addc	a, #(crc16_tab >> 8)
	mov	dph, a
	pop	dpl
	movx	a, @dptr
	mov	b, a
	inc	dph
	movx	a, @dptr
	push	a
	mov	dptr, #_crc_value + 1
	movx	a, @dptr
	xrl	a, b
	mov	dptr, #_crc_value
	movx	@dptr, a
	inc	dptr
	pop	a
	movx	@dptr, a
	pop	dpl
	pop	dph
	ret


_crc16_copy:
	push	0x00
	push	0x01
	push	0x02
	push	0x03
	push	0x04
	push	0x05
	push	0x06
	push	0x07
	mov	dptr, #_crc_cnt
	movx	a, @dptr
	mov	r4, a
	mov	r5, a
	jz	cpydone
	mov	dptr, #_crc_value
	movx	a, @dptr
	mov	r0, a
	inc	dptr
	movx	a, @dptr
	mov	r1, a
	mov	dptr, #_crc_ptr_h
	movx	a, @dptr
	mov	r2, a
	mov	dptr, #_crc_ptr_l
	movx	a, @dptr
	mov	r3, a
	mov	dptr, #_crc_dst_h
	movx	a, @dptr
	mov	r6, a
	mov	dptr, #_crc_dst_l
	movx	a, @dptr
	mov	r7, a
cpyloop:
	mov	dph, r2
	mov	dpl, r3
	movx	a, @dptr
	cjne	a, #0x0d, cpybyte
	sjmp	cpystop
cpybyte:
	inc	dptr
	mov	r2, dph
	mov	r3, dpl
	mov	dph, r6
	mov	dpl, r7
	movx	@dptr, a
	inc	dptr
	mov	r6, dph
	mov	r7, dpl
	xrl	a, r0
	add	a, #crc16_tab
	mov	dpl, a
	clr	a
	addc	a, #(crc16_tab >> 8)
	mov	dph, a
	movx	a, @dptr
	xrl	a, r1
	mov	r0, a
	inc	dph
	movx	a, @dptr
	mov	r1, a
	djnz	r4, cpyloop
cpystop:
	mov	dptr, #_crc_value
	mov	a, r0
	movx	@dptr, a
	inc	dptr
	mov	a, r1
	movx	@dptr, a
	mov	a, r5
	clr	c
	subb	a, r4
cpydone:
	mov	dpl, a
	pop	0x07
	pop	0x06
	pop	0x05
	pop	0x04
	pop	0x03
	pop	0x02
	pop	0x01
	pop	0x00
	ret


_crc16_init:
	push	0x00
	push	0x01
	push	0x02
	push	0x03
	mov	r2, #0
initloop:
	mov	a, r2
	mov	r0, a
	mov	r1, #0
	mov	r3, #8
initbit:
	clr	c
	mov	a, r1
	rrc	a
	mov	r1, a
	mov	a, r0
	rrc	a
	mov	r0, a
	jnc	initnox
	xrl	0x00, #0x01
	xrl	0x01, #0xa0
initnox:
	djnz	r3, initbit
	mov	a, r2
	add	a, #crc16_tab
	mov	dpl, a
	clr	a
	addc	a, #(crc16_tab >> 8)
	mov	dph, a
	mov	a, r0
	movx	@dptr, a
	inc	dph
	mov	a, r1
	movx	@dptr, a
	djnz	r2, initloop
	pop	0x03
	pop	0x02
	pop	0x01
	pop	0x00
	ret

	.area BANK1   (CODE)

_crc16:
	lcall	_crc16_bank1
	ljmp	__sdcc_banked_ret
