#ifndef _KALLSYMS_LOOKUP_API_H_
#define _KALLSYMS_LOOKUP_API_H_

#include "ver_control.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <asm/ptrace.h>

typedef void (*hwbp_do_mem_abort_t)(unsigned long far, unsigned long esr,
	struct pt_regs *regs);
typedef void (*hwbp_do_debug_exception_t)(unsigned long addr_if_watchpoint,
	unsigned long esr, struct pt_regs *regs);
typedef ssize_t (*hwbp_pagemap_read_t)(struct file *file, char __user *buf,
	size_t count, loff_t *ppos);
typedef void (*hwbp_user_single_step_t)(struct task_struct *task);

static unsigned long (*kallsyms_lookup_name_sym)(const char *name);
static hwbp_do_mem_abort_t do_mem_abort_sym;
static hwbp_do_debug_exception_t do_debug_exception_sym;
static hwbp_pagemap_read_t pagemap_read_sym;
static hwbp_user_single_step_t user_enable_single_step_sym;
static hwbp_user_single_step_t user_disable_single_step_sym;
static int (*aarch64_insn_patch_text_nosync_sym)(void *addr, u32 insn);

struct user_fpsimd_state;
static void (*fpsimd_preserve_current_state_sym)(void);
static void (*fpsimd_update_current_state_sym)(struct user_fpsimd_state const *state);

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static unsigned long get_kallsyms_func(void)
{
	int ret;
	unsigned long addr = 0;
	struct kprobe probe = {0};

	probe.pre_handler = _kallsyms_lookup_kprobe;
	probe.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&probe);
	if (ret == 0) {
		addr = (unsigned long)probe.addr;
		printk_debug(KERN_EMERG "get_kallsyms_func(kallsyms_lookup_name):%px\n", (void *)addr);
		unregister_kprobe(&probe);
	}
	return addr;
}

static unsigned long generic_kallsyms_lookup_name(const char *name)
{
	if (!kallsyms_lookup_name_sym) {
		kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
		printk_debug(KERN_EMERG "get_kallsyms_func:%px\n", kallsyms_lookup_name_sym);
		if (!kallsyms_lookup_name_sym) {
			return 0;
		}
	}
	return kallsyms_lookup_name_sym(name);
}

static bool init_kallsyms_lookup(void)
{
	do_mem_abort_sym = (void *)generic_kallsyms_lookup_name("do_mem_abort");
	printk_debug(KERN_EMERG "do_mem_abort_sym:%px\n", do_mem_abort_sym);
	if (!do_mem_abort_sym) {
		return false;
	}

	do_debug_exception_sym = (void *)generic_kallsyms_lookup_name("do_debug_exception");
	printk_debug(KERN_EMERG "do_debug_exception_sym:%px\n", do_debug_exception_sym);
	if (!do_debug_exception_sym) {
		return false;
	}

	pagemap_read_sym = (void *)generic_kallsyms_lookup_name("pagemap_read");
	printk_debug(KERN_EMERG "pagemap_read_sym:%px\n", pagemap_read_sym);
	if (!pagemap_read_sym) {
		return false;
	}

	user_enable_single_step_sym =
		(void *)generic_kallsyms_lookup_name("user_enable_single_step");
	printk_debug(KERN_EMERG "user_enable_single_step_sym:%px\n",
		user_enable_single_step_sym);
	if (!user_enable_single_step_sym) {
		return false;
	}

	user_disable_single_step_sym =
		(void *)generic_kallsyms_lookup_name("user_disable_single_step");
	printk_debug(KERN_EMERG "user_disable_single_step_sym:%px\n",
		user_disable_single_step_sym);
	if (!user_disable_single_step_sym) {
		return false;
	}

	aarch64_insn_patch_text_nosync_sym =
		(void *)generic_kallsyms_lookup_name("aarch64_insn_patch_text_nosync");
	printk_debug(KERN_EMERG "aarch64_insn_patch_text_nosync_sym:%px\n",
		aarch64_insn_patch_text_nosync_sym);

	fpsimd_preserve_current_state_sym =
		(void *)generic_kallsyms_lookup_name("fpsimd_preserve_current_state");
	printk_debug(KERN_EMERG "fpsimd_preserve_current_state_sym:%px\n",
		fpsimd_preserve_current_state_sym);
	if (!fpsimd_preserve_current_state_sym) {
		return false;
	}

	fpsimd_update_current_state_sym =
		(void *)generic_kallsyms_lookup_name("fpsimd_update_current_state");
	printk_debug(KERN_EMERG "fpsimd_update_current_state_sym:%px\n",
		fpsimd_update_current_state_sym);
	if (!fpsimd_update_current_state_sym) {
		return false;
	}

	return true;
}

#endif
