/*
 * Host-build shim for rtl837x_sfr.h - SFR access is hardware-only, so the
 * read is mocked: TX-complete and table-busy polls see "done" at once, which
 * keeps the bounded wait loops from spinning out their guard counters.
 */
#ifndef _SHIM_RTL837X_SFR_H_
#define _SHIM_RTL837X_SFR_H_

extern unsigned char sfr_data[4];

#endif
