/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Firmware-Assisted Dump support on POWER platform (OPAL).
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 */

#ifndef __PPC64_OPAL_FA_DUMP_H__
#define __PPC64_OPAL_FA_DUMP_H__

/* OPAL FADump structure format version */
#define OPAL_FADUMP_VERSION			0x1

/* Maximum number of memory regions kernel supports */
#define OPAL_FADUMP_MAX_MEM_REGS		128

/*
 * FADump memory structure for storing kernel metadata needed to
 * register-for/process crash dump. The address of this structure will
 * be registered with f/w for retrieving during crash dump.
 */
struct opal_fadump_mem_struct {

	u8	version;
	u8	reserved[3];
	u16	region_cnt;		/* number of regions */
	u16	registered_regions;	/* Regions registered for MPIPL */
	u64	fadumphdr_addr;
	struct opal_mpipl_region	rgn[OPAL_FADUMP_MAX_MEM_REGS];
} __attribute__((packed));

#endif /* __PPC64_OPAL_FA_DUMP_H__ */
