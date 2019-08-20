// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Firmware-Assisted Dump support on POWER platform (OPAL).
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 */

#undef DEBUG
#define pr_fmt(fmt) "opal fadump: " fmt

#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/crash_dump.h>

#include <asm/page.h>
#include <asm/opal.h>

#include "../../kernel/fadump-common.h"
#include "opal-fadump.h"


#ifdef CONFIG_PRESERVE_FA_DUMP
/*
 * When dump is active but PRESERVE_FA_DUMP is enabled on the kernel,
 * ensure crash data is preserved in hope that the subsequent memory
 * preserving kernel boot is going to process this crash data.
 */
int __init opal_fadump_dt_scan(struct fw_dump *fadump_conf, ulong node)
{
	unsigned long dn;
	const __be32 *prop;

	dn = of_get_flat_dt_subnode_by_name(node, "dump");
	if (dn == -FDT_ERR_NOTFOUND)
		return 1;

	/*
	 * Check if dump has been initiated on last reboot.
	 */
	prop = of_get_flat_dt_prop(dn, "mpipl-boot", NULL);
	if (prop) {
		u64 addr = 0;
		s64 ret;
		const struct opal_fadump_mem_struct *r_opal_fdm_active;

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_KERNEL, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_debug("Could not get Kernel metadata (%lld)\n", ret);
			return 1;
		}

		/*
		 * Preserve memory only if kernel memory regions are registered
		 * with f/w for MPIPL.
		 */
		addr = be64_to_cpu(addr);
		pr_debug("Kernel metadata addr: %llx\n", addr);
		r_opal_fdm_active = (void *)addr;
		if (r_opal_fdm_active->registered_regions == 0)
			return 1;

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_BOOT_MEM, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_err("Failed to get boot memory tag (%lld)\n", ret);
			return 1;
		}

		/*
		 * Anything below this address can be used for booting a
		 * capture kernel or petitboot kernel. Preserve everything
		 * above this address for processing crashdump.
		 */
		fadump_conf->boot_mem_top = be64_to_cpu(addr);
		pr_debug("Preserve everything above %lx\n",
			 fadump_conf->boot_mem_top);

		pr_info("Firmware-assisted dump is active.\n");
		fadump_conf->dump_active = 1;
	}

	return 1;
}

#else /* CONFIG_PRESERVE_FA_DUMP */
static const struct opal_fadump_mem_struct *opal_fdm_active;
static const struct opal_mpipl_fadump *opal_cpu_metadata;
static struct opal_fadump_mem_struct *opal_fdm;

#ifdef CONFIG_OPAL_CORE
extern bool kernel_initiated;
#endif

static int opal_fadump_unregister(struct fw_dump *fadump_conf);

static void opal_fadump_update_config(struct fw_dump *fadump_conf,
				      const struct opal_fadump_mem_struct *fdm)
{
	pr_debug("Boot memory regions count: %d\n", fdm->region_cnt);

	/*
	 * The destination address of the first boot memory region is the
	 * destination address of boot memory regions.
	 */
	fadump_conf->boot_mem_dest_addr = fdm->rgn[0].dest;
	pr_debug("Destination address of boot memory regions: %#016lx\n",
		 fadump_conf->boot_mem_dest_addr);

	fadump_conf->fadumphdr_addr = fdm->fadumphdr_addr;
}

/*
 * This function is called in the capture kernel to get configuration details
 * from metadata setup by the first kernel.
 */
static void opal_fadump_get_config(struct fw_dump *fadump_conf,
				   const struct opal_fadump_mem_struct *fdm)
{
	int i;

	if (!fadump_conf->dump_active)
		return;

	fadump_conf->boot_memory_size = 0;

	pr_debug("Boot memory regions:\n");
	for (i = 0; i < fdm->region_cnt; i++) {
		pr_debug("\t%d. base: 0x%llx, size: 0x%llx\n",
			 (i + 1), fdm->rgn[i].src, fdm->rgn[i].size);

		fadump_conf->boot_memory_size += fdm->rgn[i].size;
	}

	/*
	 * Start address of reserve dump area (permanent reservation) for
	 * re-registering FADump after dump capture.
	 */
	fadump_conf->reserve_dump_area_start = fdm->rgn[0].dest;

	/*
	 * Rarely, but it can so happen that system crashes before all
	 * boot memory regions are registered for MPIPL. In such
	 * cases, warn that the vmcore may not be accurate and proceed
	 * anyway as that is the best bet considering free pages, cache
	 * pages, user pages, etc are usually filtered out.
	 *
	 * Hope the memory that could not be preserved only has pages
	 * that are usually filtered out while saving the vmcore.
	 */
	if (fdm->region_cnt > fdm->registered_regions) {
		pr_warn("Not all memory regions are saved as system seems to have crashed before all the memory regions could be registered for MPIPL!\n");
		pr_warn("  The below boot memory regions could not be saved:\n");
		i = fdm->registered_regions;
		while (i < fdm->region_cnt) {
			pr_warn("\t%d. base: 0x%llx, size: 0x%llx\n", (i + 1),
				fdm->rgn[i].src, fdm->rgn[i].size);
			i++;
		}

		pr_warn("  Wishing for the above regions to have only pages that are usually filtered out (user pages, free pages, etc..) and proceeding anyway..\n");
		pr_warn("  But the sanity of the '/proc/vmcore' file depends on whether the above region(s) have any kernel pages or not.\n");
	}

	opal_fadump_update_config(fadump_conf, fdm);
}

/* Initialize kernel metadata */
static void opal_fadump_init_metadata(struct opal_fadump_mem_struct *fdm)
{
	fdm->version = OPAL_FADUMP_VERSION;
	fdm->region_cnt = 0;
	fdm->registered_regions = 0;
	fdm->fadumphdr_addr = 0;
}

static ulong opal_fadump_init_mem_struct(struct fw_dump *fadump_conf)
{
	ulong src_addr, dest_addr;
	int max_copy_size, cur_size, size;

	opal_fdm = __va(fadump_conf->kernel_metadata);
	opal_fadump_init_metadata(opal_fdm);

	/*
	 * Firmware currently supports only 32-bit value for size,
	 * align it to pagesize and request firmware to copy multiple
	 * kernel boot memory regions.
	 */
	max_copy_size = _ALIGN_DOWN(U32_MAX, PAGE_SIZE);

	/* Boot memory regions */
	src_addr = RMA_START;
	dest_addr = fadump_conf->reserve_dump_area_start;
	size = fadump_conf->boot_memory_size;
	while (size) {
		cur_size = size > max_copy_size ? max_copy_size : size;

		opal_fdm->rgn[opal_fdm->region_cnt].src  = src_addr;
		opal_fdm->rgn[opal_fdm->region_cnt].dest = dest_addr;
		opal_fdm->rgn[opal_fdm->region_cnt].size = cur_size;

		opal_fdm->region_cnt++;
		dest_addr	+= cur_size;
		src_addr	+= cur_size;
		size		-= cur_size;
	}

	/*
	 * Kernel metadata is passed to f/w and retrieved in capture kerenl.
	 * So, use it to save fadump header address instead of calculating it.
	 */
	opal_fdm->fadumphdr_addr = (opal_fdm->rgn[0].dest +
				    fadump_conf->boot_memory_size);

	opal_fadump_update_config(fadump_conf, opal_fdm);

	return dest_addr;
}

static ulong opal_fadump_get_metadata_size(void)
{
	ulong size = sizeof(struct opal_fadump_mem_struct);

	size = PAGE_ALIGN(size);
	return size;
}

static int opal_fadump_setup_metadata(struct fw_dump *fadump_conf)
{
	int err = 0;
	s64 ret;

	/*
	 * Use the last page(s) in FADump memory reservation for
	 * kernel metadata.
	 */
	fadump_conf->kernel_metadata = (fadump_conf->reserve_dump_area_start +
					fadump_conf->reserve_dump_area_size -
					opal_fadump_get_metadata_size());
	pr_info("Kernel metadata addr: %llx\n", fadump_conf->kernel_metadata);

	/* Initialize kernel metadata before registering the address with f/w */
	opal_fdm = __va(fadump_conf->kernel_metadata);
	opal_fadump_init_metadata(opal_fdm);

	/*
	 * Register metadata address with f/w. Can be retrieved in
	 * the capture kernel.
	 */
	ret = opal_mpipl_register_tag(OPAL_MPIPL_TAG_KERNEL,
				      fadump_conf->kernel_metadata);
	if (ret != OPAL_SUCCESS) {
		pr_err("Failed to set kernel metadata tag!\n");
		err = -EPERM;
	}

	/*
	 * Register boot memory top address with f/w. Should be retrieved
	 * by a kernel that intends to preserve crash'ed kernel's memory.
	 */
	ret = opal_mpipl_register_tag(OPAL_MPIPL_TAG_BOOT_MEM,
				      fadump_conf->boot_memory_size);
	if (ret != OPAL_SUCCESS) {
		pr_err("Failed to set boot memory tag!\n");
		err = -EPERM;
	}

	return err;
}

static ulong opal_fadump_get_bootmem_min(void)
{
	return OPAL_FADUMP_MIN_BOOT_MEM;
}

static int opal_fadump_register(struct fw_dump *fadump_conf)
{
	int i, err = -EIO;
	s64 rc = -INT_MAX;

	for (i = 0; i < opal_fdm->region_cnt; i++) {
		rc = opal_mpipl_update(OPAL_MPIPL_ADD_RANGE,
				       opal_fdm->rgn[i].src,
				       opal_fdm->rgn[i].dest,
				       opal_fdm->rgn[i].size);
		if (rc != OPAL_SUCCESS)
			break;

		opal_fdm->registered_regions++;
	}

	switch (rc) {
	case OPAL_SUCCESS:
		pr_info("Registration is successful!\n");
		fadump_conf->dump_registered = 1;
		err = 0;
		break;
	case OPAL_RESOURCE:
		/* If MAX regions limit in f/w is hit, warn and proceed. */
		pr_warn("%d regions could not be registered for MPIPL as MAX limit is reached!\n",
			(opal_fdm->region_cnt - opal_fdm->registered_regions));
		fadump_conf->dump_registered = 1;
		err = 0;
		break;
	case OPAL_PARAMETER:
		pr_err("Failed to register. Parameter Error(%lld).\n", rc);
		break;
	case OPAL_HARDWARE:
		pr_err("Support not available.\n");
		fadump_conf->fadump_supported = 0;
		fadump_conf->fadump_enabled = 0;
		break;
	default:
		pr_err("Failed to register. Unknown Error(%lld).\n", rc);
		break;
	}

	/*
	 * If some regions were registered before OPAL_MPIPL_ADD_RANGE
	 * OPAL call failed, unregister all regions.
	 */
	if ((err < 0) && (opal_fdm->registered_regions > 0))
		opal_fadump_unregister(fadump_conf);

	return err;
}

static int opal_fadump_unregister(struct fw_dump *fadump_conf)
{
	s64 rc;

	rc = opal_mpipl_update(OPAL_MPIPL_REMOVE_ALL, 0, 0, 0);
	if (rc) {
		pr_err("Failed to un-register - unexpected Error(%lld).\n", rc);
		return -EIO;
	}

	opal_fdm->registered_regions = 0;
	fadump_conf->dump_registered = 0;
	return 0;
}

static int opal_fadump_invalidate(struct fw_dump *fadump_conf)
{
	s64 rc;

	rc = opal_mpipl_update(OPAL_MPIPL_FREE_PRESERVED_MEMORY, 0, 0, 0);
	if (rc) {
		pr_err("Failed to invalidate - unexpected Error(%lld).\n", rc);
		return -EIO;
	}

	fadump_conf->dump_active = 0;
	opal_fdm_active = NULL;
	return 0;
}

static void opal_fadump_cleanup(struct fw_dump *fadump_conf)
{
	s64 ret;

	ret = opal_mpipl_register_tag(OPAL_MPIPL_TAG_KERNEL, 0);
	if (ret != OPAL_SUCCESS)
		pr_warn("Could not reset (%llu) kernel metadata tag!\n", ret);
}

/*
 * Convert CPU state data saved at the time of crash into ELF notes.
 *
 * Each register entry is of 16 bytes, A numerical identifier along with
 * a GPR/SPR flag in the first 8 bytes and the register value in the next
 * 8 bytes. For more details refer to F/W documentation.
 */
static int __init opal_fadump_build_cpu_notes(struct fw_dump *fadump_conf)
{
	u32 num_cpus, *note_buf;
	struct fadump_crash_info_header *fdh = NULL;
	struct hdat_fadump_thread_hdr *thdr;
	unsigned long addr;
	u32 thread_pir;
	char *bufp;
	struct pt_regs regs;
	unsigned int size_of_each_thread;
	unsigned int regs_offset, regs_cnt, reg_esize;
	int i;

	fadump_conf->cpu_state_entry_size =
			be32_to_cpu(opal_cpu_metadata->cpu_data_size);
	fadump_conf->cpu_state_destination_addr =
			be64_to_cpu(opal_cpu_metadata->region[0].dest);
	fadump_conf->cpu_state_data_size =
			be64_to_cpu(opal_cpu_metadata->region[0].size);

	if ((fadump_conf->cpu_state_destination_addr == 0) ||
	    (fadump_conf->cpu_state_entry_size == 0)) {
		pr_err("CPU state data not available for processing!\n");
		return -ENODEV;
	}

	size_of_each_thread = fadump_conf->cpu_state_entry_size;
	num_cpus = (fadump_conf->cpu_state_data_size / size_of_each_thread);

	addr = fadump_conf->cpu_state_destination_addr;
	bufp = __va(addr);

	/*
	 * Offset for register entries, entry size and registers count is
	 * duplicated in every thread header in keeping with HDAT format.
	 * Use these values from the first thread header.
	 */
	thdr = (struct hdat_fadump_thread_hdr *)bufp;
	regs_offset = (offsetof(struct hdat_fadump_thread_hdr, offset) +
		       be32_to_cpu(thdr->offset));
	reg_esize = be32_to_cpu(thdr->esize);
	regs_cnt  = be32_to_cpu(thdr->ecnt);

	/* Allocate buffer to hold cpu crash notes. */
	fadump_conf->cpu_notes_buf_size = num_cpus * sizeof(note_buf_t);
	fadump_conf->cpu_notes_buf_size =
		PAGE_ALIGN(fadump_conf->cpu_notes_buf_size);
	note_buf = fadump_cpu_notes_buf_alloc(fadump_conf->cpu_notes_buf_size);
	if (!note_buf) {
		pr_err("Failed to allocate 0x%lx bytes for cpu notes buffer\n",
		       fadump_conf->cpu_notes_buf_size);
		return -ENOMEM;
	}
	fadump_conf->cpu_notes_buf = __pa(note_buf);

	pr_debug("Allocated buffer for cpu notes of size %ld at %p\n",
		 (num_cpus * sizeof(note_buf_t)), note_buf);

	if (fadump_conf->fadumphdr_addr)
		fdh = __va(fadump_conf->fadumphdr_addr);

	pr_debug("--------CPU State Data------------\n");
	pr_debug("NumCpus     : %u\n", num_cpus);
	pr_debug("\tOffset: %u, Entry size: %u, Cnt: %u\n",
		 regs_offset, reg_esize, regs_cnt);

	for (i = 0; i < num_cpus; i++, bufp += size_of_each_thread) {
		thdr = (struct hdat_fadump_thread_hdr *)bufp;

		thread_pir = be32_to_cpu(thdr->pir);
		pr_debug("%04d) PIR: 0x%x, core state: 0x%02x\n",
			 (i + 1), thread_pir, thdr->core_state);

		/*
		 * Register state data of MAX cores is provided by firmware,
		 * but some of this cores may not be active. So, while
		 * processing register state data, check core state and
		 * skip threads that belong to inactive cores.
		 */
		if (is_thread_core_inactive(thdr->core_state))
			continue;

		/*
		 * If this is kernel initiated crash, crashing_cpu would be set
		 * appropriately and register data of the crashing CPU saved by
		 * crashing kernel. Add this saved register data of crashing CPU
		 * to elf notes and populate the pt_regs for the remaining CPUs
		 * from register state data provided by firmware.
		 */
		if (fdh && (fdh->crashing_cpu == thread_pir)) {
			note_buf = fadump_regs_to_elf_notes(note_buf,
							    &fdh->regs);
			pr_debug("Crashing CPU PIR: 0x%x - R1 : 0x%lx, NIP : 0x%lx\n",
				 fdh->crashing_cpu, fdh->regs.gpr[1],
				 fdh->regs.nip);
			continue;
		}

		opal_fadump_read_regs((bufp + regs_offset), regs_cnt,
				      reg_esize, true, &regs);

		note_buf = fadump_regs_to_elf_notes(note_buf, &regs);
		pr_debug("CPU PIR: 0x%x - R1 : 0x%lx, NIP : 0x%lx\n",
			 thread_pir, regs.gpr[1], regs.nip);
	}
	final_note(note_buf);

	if (fdh) {
		pr_debug("Updating elfcore header (%llx) with cpu notes\n",
			 fdh->elfcorehdr_addr);
		fadump_update_elfcore_header(fadump_conf,
					     __va(fdh->elfcorehdr_addr));
	}

	return 0;
}

static int __init opal_fadump_process(struct fw_dump *fadump_conf)
{
	struct fadump_crash_info_header *fdh;
	int rc = 0;

	if (!opal_fdm_active || !opal_cpu_metadata ||
	    !fadump_conf->fadumphdr_addr)
		return -EINVAL;

	/* Validate the fadump crash info header */
	fdh = __va(fadump_conf->fadumphdr_addr);
	if (fdh->magic_number != FADUMP_CRASH_INFO_MAGIC) {
		pr_err("Crash info header is not valid.\n");
		return -EINVAL;
	}

#ifdef CONFIG_OPAL_CORE
	/*
	 * If this is a kernel initiated crash, crashing_cpu would be set
	 * appropriately and register data of the crashing CPU saved by
	 * crashing kernel. Add this saved register data of crashing CPU
	 * to elf notes and populate the pt_regs for the remaining CPUs
	 * from register state data provided by firmware.
	 */
	if (fdh->crashing_cpu != FADUMP_CPU_UNKNOWN)
		kernel_initiated = true;
#endif

	rc = opal_fadump_build_cpu_notes(fadump_conf);
	if (rc)
		return rc;

	/*
	 * We are done validating dump info and elfcore header is now ready
	 * to be exported. set elfcorehdr_addr so that vmcore module will
	 * export the elfcore header through '/proc/vmcore'.
	 */
	elfcorehdr_addr = fdh->elfcorehdr_addr;

	return rc;
}

static void opal_fadump_region_show(struct fw_dump *fadump_conf,
				    struct seq_file *m)
{
	int i;
	const struct opal_fadump_mem_struct *fdm_ptr;
	u64 dumped_bytes = 0;

	if (fadump_conf->dump_active)
		fdm_ptr = opal_fdm_active;
	else
		fdm_ptr = opal_fdm;

	for (i = 0; i < fdm_ptr->region_cnt; i++) {
		/*
		 * Only regions that are registered for MPIPL
		 * would have dump data.
		 */
		if ((fadump_conf->dump_active) &&
		    (i < fdm_ptr->registered_regions))
			dumped_bytes = fdm_ptr->rgn[i].size;

		seq_printf(m, "DUMP: Src: %#016llx, Dest: %#016llx, ",
			   fdm_ptr->rgn[i].src, fdm_ptr->rgn[i].dest);
		seq_printf(m, "Size: %#llx, Dumped: %#llx bytes\n",
			   fdm_ptr->rgn[i].size, dumped_bytes);
	}

	/* Dump is active. Show reserved area start address. */
	if (fadump_conf->dump_active) {
		seq_printf(m, "\nMemory above %#016lx is reserved for saving crash dump\n",
			   fadump_conf->reserve_dump_area_start);
	}
}

static void opal_fadump_trigger(struct fadump_crash_info_header *fdh,
				const char *msg)
{
	int rc;

	/*
	 * Unlike on pSeries platform, logical CPU number is not provided
	 * with architected register state data. So, store the crashing
	 * CPU's PIR instead to plug the appropriate register data for
	 * crashing CPU in the vmcore file.
	 */
	fdh->crashing_cpu = (u32)mfspr(SPRN_PIR);

	rc = opal_cec_reboot2(OPAL_REBOOT_MPIPL, msg);
	if (rc == OPAL_UNSUPPORTED) {
		pr_emerg("Reboot type %d not supported.\n",
			 OPAL_REBOOT_MPIPL);
	} else if (rc == OPAL_HARDWARE)
		pr_emerg("No backend support for MPIPL!\n");
}

static struct fadump_ops opal_fadump_ops = {
	.fadump_init_mem_struct		= opal_fadump_init_mem_struct,
	.fadump_get_metadata_size	= opal_fadump_get_metadata_size,
	.fadump_setup_metadata		= opal_fadump_setup_metadata,
	.fadump_get_bootmem_min		= opal_fadump_get_bootmem_min,
	.fadump_register		= opal_fadump_register,
	.fadump_unregister		= opal_fadump_unregister,
	.fadump_invalidate		= opal_fadump_invalidate,
	.fadump_cleanup			= opal_fadump_cleanup,
	.fadump_process			= opal_fadump_process,
	.fadump_region_show		= opal_fadump_region_show,
	.fadump_trigger			= opal_fadump_trigger,
};

int __init opal_fadump_dt_scan(struct fw_dump *fadump_conf, ulong node)
{
	unsigned long dn;
	const __be32 *prop;
	int i, len;

	/*
	 * Check if Firmware-Assisted Dump is supported. if yes, check
	 * if dump has been initiated on last reboot.
	 */
	dn = of_get_flat_dt_subnode_by_name(node, "dump");
	if (dn == -FDT_ERR_NOTFOUND) {
		pr_debug("FADump support is missing!\n");
		return 1;
	}

	if (!of_flat_dt_is_compatible(dn, "ibm,opal-dump")) {
		pr_err("Support missing for this f/w version!\n");
		return 1;
	}

	prop = of_get_flat_dt_prop(dn, "fw-load-area", &len);
	if (prop) {
		/*
		 * Each f/w load area is an (address,size) pair,
		 * 2 cells each, totalling 4 cells per range.
		 */
		for (i = 0; i < len / (sizeof(*prop) * 4); i++) {
			u64 base, end;

			base = of_read_number(prop + (i * 4) + 0, 2);
			end = base;
			end += of_read_number(prop + (i * 4) + 2, 2);
			if (end > OPAL_FADUMP_MIN_BOOT_MEM) {
				pr_err("F/W load area: 0x%llx-0x%llx\n",
				       base, end);
				pr_err("F/W version not supported!\n");
				return 1;
			}
		}
	}

	fadump_conf->ops		= &opal_fadump_ops;
	fadump_conf->fadump_supported	= 1;

	/*
	 * Check if dump has been initiated on last reboot.
	 */
	prop = of_get_flat_dt_prop(dn, "mpipl-boot", NULL);
	if (prop) {
		u64 addr = 0;
		s64 ret;
		const struct opal_fadump_mem_struct *r_opal_fdm_active;
		const struct opal_mpipl_fadump *r_opal_cpu_metadata;

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_KERNEL, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_err("Failed to get Kernel metadata (%lld)\n", ret);
			return 1;
		}

		addr = be64_to_cpu(addr);
		pr_debug("Kernel metadata addr: %llx\n", addr);

		opal_fdm_active = __va(addr);
		r_opal_fdm_active = (void *)addr;
		if (r_opal_fdm_active->version != OPAL_FADUMP_VERSION) {
			pr_err("FADump active but version (%u) unsupported!\n",
			       r_opal_fdm_active->version);
			return 1;
		}

		/* Kernel regions not registered with f/w for MPIPL */
		if (r_opal_fdm_active->registered_regions == 0) {
			opal_fdm_active = NULL;
			return 1;
		}

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_CPU, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_err("Failed to get CPU metadata (%lld)\n", ret);
			return 1;
		}

		addr = be64_to_cpu(addr);
		pr_debug("CPU metadata addr: %llx\n", addr);

		opal_cpu_metadata = __va(addr);
		r_opal_cpu_metadata = (void *)addr;
		fadump_conf->cpu_state_data_version =
			be32_to_cpu(r_opal_cpu_metadata->cpu_data_version);
		if (fadump_conf->cpu_state_data_version !=
		    HDAT_FADUMP_CPU_DATA_VERSION) {
			pr_err("CPU data format version (%lu) mismatch!\n",
			       fadump_conf->cpu_state_data_version);
			return 1;
		}

		pr_info("Firmware-assisted dump is active.\n");
		fadump_conf->dump_active = 1;
		opal_fadump_get_config(fadump_conf, r_opal_fdm_active);
	}

	return 1;
}
#endif /* !CONFIG_PRESERVE_FA_DUMP */
