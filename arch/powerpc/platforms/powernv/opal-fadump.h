/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Firmware-Assisted Dump support on POWER platform (OPAL).
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 */

#ifndef __PPC64_OPAL_FA_DUMP_H__
#define __PPC64_OPAL_FA_DUMP_H__

#include <asm/reg.h>

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

/*
 * CPU state data is provided by f/w. Below are the definitions
 * provided in HDAT spec. Refer to latest HDAT specification for
 * any update to this format.
 */

#define HDAT_FADUMP_CPU_DATA_VERSION		1

#define HDAT_FADUMP_CORE_INACTIVE		(0x0F)

/* HDAT thread header for register entries */
struct hdat_fadump_thread_hdr {
	__be32  pir;
	/* 0x00 - 0x0F - The corresponding stop state of the core */
	u8      core_state;
	u8      reserved[3];

	__be32	offset;	/* Offset to Register Entries array */
	__be32	ecnt;	/* Number of entries */
	__be32	esize;	/* Alloc size of each array entry in bytes */
	__be32	eactsz;	/* Actual size of each array entry in bytes */
} __attribute__((packed));

/* Register types populated by f/w */
#define HDAT_FADUMP_REG_TYPE_GPR		0x01
#define HDAT_FADUMP_REG_TYPE_SPR		0x02

/* ID numbers used by f/w while populating certain registers */
#define HDAT_FADUMP_REG_ID_NIP			0x7D0
#define HDAT_FADUMP_REG_ID_MSR			0x7D1
#define HDAT_FADUMP_REG_ID_CCR			0x7D2

/* HDAT register entry. */
struct hdat_fadump_reg_entry {
	__be32		reg_type;
	__be32		reg_num;
	__be64		reg_val;
} __attribute__((packed));

static inline bool __init is_thread_core_inactive(u8 core_state)
{
	bool is_inactive = false;

	if (core_state == HDAT_FADUMP_CORE_INACTIVE)
		is_inactive = true;

	return is_inactive;
}

static inline void opal_fadump_set_regval_regnum(struct pt_regs *regs,
						 u32 reg_type, u32 reg_num,
						 u64 reg_val)
{
	if (reg_type == HDAT_FADUMP_REG_TYPE_GPR) {
		if (reg_num < 32)
			regs->gpr[reg_num] = reg_val;
		return;
	}

	switch (reg_num) {
	case SPRN_CTR:
		regs->ctr = reg_val;
		break;
	case SPRN_LR:
		regs->link = reg_val;
		break;
	case SPRN_XER:
		regs->xer = reg_val;
		break;
	case SPRN_DAR:
		regs->dar = reg_val;
		break;
	case SPRN_DSISR:
		regs->dsisr = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_NIP:
		regs->nip = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_MSR:
		regs->msr = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_CCR:
		regs->ccr = reg_val;
		break;
	}
}

static inline void opal_fadump_read_regs(char *bufp, unsigned int regs_cnt,
					 unsigned int reg_entry_size,
					 bool cpu_endian,
					 struct pt_regs *regs)
{
	int i;
	u64 val;
	struct hdat_fadump_reg_entry *reg_entry;

	memset(regs, 0, sizeof(struct pt_regs));

	for (i = 0; i < regs_cnt; i++, bufp += reg_entry_size) {
		reg_entry = (struct hdat_fadump_reg_entry *)bufp;
		val = (cpu_endian ? be64_to_cpu(reg_entry->reg_val) :
		       reg_entry->reg_val);
		opal_fadump_set_regval_regnum(regs,
					      be32_to_cpu(reg_entry->reg_type),
					      be32_to_cpu(reg_entry->reg_num),
					      val);
	}
}

#endif /* __PPC64_OPAL_FA_DUMP_H__ */
