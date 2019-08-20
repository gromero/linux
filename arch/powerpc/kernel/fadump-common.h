/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Firmware-Assisted Dump internal code.
 *
 * Copyright 2011, IBM Corporation
 * Author: Mahesh Salgaonkar <mahesh@linux.ibm.com>
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 */

#ifndef __PPC64_FA_DUMP_INTERNAL_H__
#define __PPC64_FA_DUMP_INTERNAL_H__

/*
 * The RMA region will be saved for later dumping when kernel crashes.
 * RMA is Real Mode Area, the first block of logical memory address owned
 * by logical partition, containing the storage that may be accessed with
 * translate off.
 */
#define RMA_START	0x0
#define RMA_END		(ppc64_rma_size)

/*
 * On some Power systems where RMO is 128MB, it still requires minimum of
 * 256MB for kernel to boot successfully. When kdump infrastructure is
 * configured to save vmcore over network, we run into OOM issue while
 * loading modules related to network setup. Hence we need additional 64M
 * of memory to avoid OOM issue.
 */
#define MIN_BOOT_MEM	(((RMA_END < (0x1UL << 28)) ? (0x1UL << 28) : RMA_END) \
			+ (0x1UL << 26))

/* The upper limit percentage for user specified boot memory size (25%) */
#define MAX_BOOT_MEM_RATIO			4

#define memblock_num_regions(memblock_type)	(memblock.memblock_type.cnt)

/* Alignment per CMA requirement. */
#define FADUMP_CMA_ALIGNMENT	(PAGE_SIZE <<				\
				 max_t(unsigned long, MAX_ORDER - 1,	\
				 pageblock_order))

/* FAD commands */
#define FADUMP_REGISTER			1
#define FADUMP_UNREGISTER		2
#define FADUMP_INVALIDATE		3

#define FADUMP_CRASH_INFO_MAGIC		str_to_u64("FADMPINF")

/* fadump crash info structure */
struct fadump_crash_info_header {
	u64		magic_number;
	u64		elfcorehdr_addr;
	u32		crashing_cpu;
	struct pt_regs	regs;
	struct cpumask	online_mask;
};

struct fad_crash_memory_ranges {
	unsigned long long	base;
	unsigned long long	size;
};

/* Firmware-assisted dump configuration details. */
struct fw_dump {
	unsigned long	reserve_dump_area_start;
	unsigned long	reserve_dump_area_size;
	/* cmd line option during boot */
	unsigned long	reserve_bootvar;

	unsigned long	cpu_state_data_size;
	unsigned long	hpte_region_size;
	unsigned long	boot_memory_size;

	unsigned long	fadumphdr_addr;
	unsigned long	cpu_notes_buf;
	unsigned long	cpu_notes_buf_size;

	int		ibm_configure_kernel_dump;

	unsigned long	fadump_enabled:1;
	unsigned long	fadump_supported:1;
	unsigned long	dump_active:1;
	unsigned long	dump_registered:1;
	unsigned long	nocma:1;
};

/* Helper functions */
void *fadump_cpu_notes_buf_alloc(unsigned long size);
void fadump_cpu_notes_buf_free(unsigned long vaddr, unsigned long size);
u32 *fadump_regs_to_elf_notes(u32 *buf, struct pt_regs *regs);
void fadump_update_elfcore_header(struct fw_dump *fadump_config, char *bufp);
int is_fadump_boot_mem_contiguous(struct fw_dump *fadump_conf);
int is_fadump_reserved_mem_contiguous(struct fw_dump *fadump_conf);

#endif /* __PPC64_FA_DUMP_INTERNAL_H__ */
