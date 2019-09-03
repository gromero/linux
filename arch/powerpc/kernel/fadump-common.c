// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Firmware-Assisted Dump internal code.
 *
 * Copyright 2011, IBM Corporation
 * Author: Mahesh Salgaonkar <mahesh@linux.ibm.com>
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 */

#undef DEBUG
#define pr_fmt(fmt) "fadump: " fmt

#include <linux/memblock.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/crash_core.h>

#include "fadump-common.h"

void *fadump_cpu_notes_buf_alloc(unsigned long size)
{
	void *vaddr;
	struct page *page;
	unsigned long order, count, i;

	order = get_order(size);
	vaddr = (void *)__get_free_pages(GFP_KERNEL|__GFP_ZERO, order);
	if (!vaddr)
		return NULL;

	count = 1 << order;
	page = virt_to_page(vaddr);
	for (i = 0; i < count; i++)
		SetPageReserved(page + i);
	return vaddr;
}

void fadump_cpu_notes_buf_free(unsigned long vaddr, unsigned long size)
{
	struct page *page;
	unsigned long order, count, i;

	order = get_order(size);
	count = 1 << order;
	page = virt_to_page(vaddr);
	for (i = 0; i < count; i++)
		ClearPageReserved(page + i);
	__free_pages(page, order);
}

u32 *fadump_regs_to_elf_notes(u32 *buf, struct pt_regs *regs)
{
	struct elf_prstatus prstatus;

	memset(&prstatus, 0, sizeof(prstatus));
	/*
	 * FIXME: How do i get PID? Do I really need it?
	 * prstatus.pr_pid = ????
	 */
	elf_core_copy_kernel_regs(&prstatus.pr_reg, regs);
	buf = append_elf_note(buf, CRASH_CORE_NOTE_NAME, NT_PRSTATUS,
			      &prstatus, sizeof(prstatus));
	return buf;
}

void fadump_update_elfcore_header(struct fw_dump *fadump_conf, char *bufp)
{
	struct elfhdr *elf;
	struct elf_phdr *phdr;

	elf = (struct elfhdr *)bufp;
	bufp += sizeof(struct elfhdr);

	/* First note is a place holder for cpu notes info. */
	phdr = (struct elf_phdr *)bufp;

	if (phdr->p_type == PT_NOTE) {
		phdr->p_paddr  = fadump_conf->cpu_notes_buf;
		phdr->p_offset = phdr->p_paddr;
		phdr->p_memsz  = fadump_conf->cpu_notes_buf_size;
		phdr->p_filesz = phdr->p_memsz;
	}
}

/*
 * Returns 1, if there are no holes in memory area between d_start to d_end,
 * 0 otherwise.
 */
static int is_fadump_memory_area_contiguous(unsigned long d_start,
					    unsigned long d_end)
{
	struct memblock_region *reg;
	unsigned long start, end;
	int ret = 0;

	for_each_memblock(memory, reg) {
		start = max_t(unsigned long, d_start, reg->base);
		end = min_t(unsigned long, d_end, (reg->base + reg->size));
		if (d_start < end) {
			/* Memory hole from d_start to start */
			if (start > d_start)
				break;

			if (end == d_end) {
				ret = 1;
				break;
			}

			d_start = end + 1;
		}
	}

	return ret;
}

/*
 * Returns 1, if there are no holes in boot memory area,
 * 0 otherwise.
 */
int is_fadump_boot_mem_contiguous(struct fw_dump *fadump_conf)
{
	int i, ret = 0;
	unsigned long d_start, d_end;

	for (i = 0; i < fadump_conf->boot_mem_regs_cnt; i++) {
		d_start = fadump_conf->boot_mem_addr[i];
		d_end   = d_start + fadump_conf->boot_mem_sz[i];

		ret = is_fadump_memory_area_contiguous(d_start, d_end);
		if (!ret)
			break;
	}

	return ret;
}

/*
 * Returns 1, if there are no holes in reserved memory area,
 * 0 otherwise.
 */
int is_fadump_reserved_mem_contiguous(struct fw_dump *fadump_conf)
{
	unsigned long d_start = fadump_conf->reserve_dump_area_start;
	unsigned long d_end   = d_start + fadump_conf->reserve_dump_area_size;

	return is_fadump_memory_area_contiguous(d_start, d_end);
}
