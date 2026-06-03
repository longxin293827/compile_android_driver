#ifndef _ARM64_INLINE_HOOK_H_
#define _ARM64_INLINE_HOOK_H_

#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include "api_proxy.h"

#define HWBP_HOOK_PATCH_INSN_COUNT 4
#define HWBP_HOOK_TRAMP_INSN_COUNT 32
#define HWBP_A64_NOP 0xd503201fU
#define HWBP_A64_RET 0xd65f03c0U
#define HWBP_A64_LDR_X16_LIT8 0x58000050U
#define HWBP_A64_BR_X16 0xd61f0200U

struct hwbp_inline_hook {
	void *target;
	void *replace;
	u32 original[HWBP_HOOK_PATCH_INSN_COUNT];
	u32 patch[HWBP_HOOK_PATCH_INSN_COUNT];
	u32 trampoline[HWBP_HOOK_TRAMP_INSN_COUNT];
	void *trampoline_slot;
	bool installed;
};

asm(
	".pushsection .text, \"ax\", %progbits\n"
	".align 4\n"
	".global hwbp_hook_slot_0\n"
	".type hwbp_hook_slot_0, %function\n"
	"hwbp_hook_slot_0:\n"
	".rept 32\n"
	"nop\n"
	".endr\n"
	"ret\n"
	".size hwbp_hook_slot_0, .-hwbp_hook_slot_0\n"
	".align 4\n"
	".global hwbp_hook_slot_1\n"
	".type hwbp_hook_slot_1, %function\n"
	"hwbp_hook_slot_1:\n"
	".rept 32\n"
	"nop\n"
	".endr\n"
	"ret\n"
	".size hwbp_hook_slot_1, .-hwbp_hook_slot_1\n"
	".align 4\n"
	".global hwbp_hook_slot_2\n"
	".type hwbp_hook_slot_2, %function\n"
	"hwbp_hook_slot_2:\n"
	".rept 32\n"
	"nop\n"
	".endr\n"
	"ret\n"
	".size hwbp_hook_slot_2, .-hwbp_hook_slot_2\n"
	".popsection\n"
);

extern void hwbp_hook_slot_0(void);
extern void hwbp_hook_slot_1(void);
extern void hwbp_hook_slot_2(void);

static bool hwbp_a64_is_pc_relative_or_branch(u32 insn)
{
	if ((insn & 0x9f000000U) == 0x10000000U) {
		return true; /* ADR */
	}
	if ((insn & 0x9f000000U) == 0x90000000U) {
		return true; /* ADRP */
	}
	if ((insn & 0xfc000000U) == 0x14000000U) {
		return true; /* B/BL */
	}
	if ((insn & 0xff000010U) == 0x54000000U) {
		return true; /* conditional B */
	}
	if ((insn & 0x7f000000U) == 0x34000000U ||
	    (insn & 0x7f000000U) == 0x35000000U ||
	    (insn & 0x7f000000U) == 0x36000000U ||
	    (insn & 0x7f000000U) == 0x37000000U) {
		return true; /* CBZ/CBNZ/TBZ/TBNZ */
	}
	if ((insn & 0xff000000U) == 0x18000000U ||
	    (insn & 0xff000000U) == 0x58000000U ||
	    (insn & 0xff000000U) == 0x98000000U ||
	    (insn & 0xff000000U) == 0xd8000000U ||
	    (insn & 0xff000000U) == 0x1c000000U ||
	    (insn & 0xff000000U) == 0x5c000000U ||
	    (insn & 0xff000000U) == 0x9c000000U) {
		return true; /* literal loads/prfm */
	}
	return false;
}

static void hwbp_a64_abs_branch(u32 *buf, unsigned long addr)
{
	buf[0] = HWBP_A64_LDR_X16_LIT8;
	buf[1] = HWBP_A64_BR_X16;
	buf[2] = (u32)(addr & 0xffffffffUL);
	buf[3] = (u32)(addr >> 32);
}

static pte_t *hwbp_kernel_pte(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_k(addr);
	if (!pgd || pgd_none(READ_ONCE(*pgd))) {
		return NULL;
	}
	p4d = p4d_offset(pgd, addr);
	if (!p4d || p4d_none(READ_ONCE(*p4d))) {
		return NULL;
	}
	pud = pud_offset(p4d, addr);
	if (!pud || pud_none(READ_ONCE(*pud)) || pud_sect(READ_ONCE(*pud))) {
		return NULL;
	}
	pmd = pmd_offset(pud, addr);
	if (!pmd || pmd_none(READ_ONCE(*pmd)) || pmd_sect(READ_ONCE(*pmd))) {
		return NULL;
	}
	return pte_offset_kernel(pmd, addr);
}

static int hwbp_patch_one_nosync(void *addr, u32 insn)
{
	pte_t *ptep;
	pte_t old_pte;
	pte_t rw_pte;
	unsigned long va = (unsigned long)addr;

	if (aarch64_insn_patch_text_nosync_sym) {
		return aarch64_insn_patch_text_nosync_sym(addr, insn);
	}

	ptep = hwbp_kernel_pte(va);
	if (!ptep) {
		return -EFAULT;
	}

	old_pte = READ_ONCE(*ptep);
	rw_pte = pte_mkwrite(old_pte);
	rw_pte = clear_pte_bit(rw_pte, __pgprot(PTE_RDONLY));
	set_pte(ptep, rw_pte);
	flush_tlb_kernel_range(va & PAGE_MASK, (va & PAGE_MASK) + PAGE_SIZE);

	WRITE_ONCE(*(u32 *)addr, insn);
	flush_icache_range(va, va + sizeof(u32));

	set_pte(ptep, old_pte);
	flush_tlb_kernel_range(va & PAGE_MASK, (va & PAGE_MASK) + PAGE_SIZE);
	return 0;
}

struct hwbp_patch_set {
	void **addrs;
	u32 *insns;
	int count;
	atomic_t ready_count;
	int ret;
};

static int hwbp_patch_stop_machine_cb(void *arg)
{
	int i;
	struct hwbp_patch_set *set = arg;

	if (atomic_inc_return(&set->ready_count) == num_online_cpus()) {
		for (i = 0; i < set->count; i++) {
			set->ret = hwbp_patch_one_nosync(set->addrs[i], set->insns[i]);
			if (set->ret) {
				break;
			}
		}
		atomic_inc(&set->ready_count);
	} else {
		while (atomic_read(&set->ready_count) <= num_online_cpus()) {
			cpu_relax();
		}
		isb();
	}
	return 0;
}

static int hwbp_patch_text(void **addrs, u32 *insns, int count)
{
	struct hwbp_patch_set set = {
		.addrs = addrs,
		.insns = insns,
		.count = count,
		.ready_count = ATOMIC_INIT(0),
		.ret = 0,
	};
	int ret;

	ret = stop_machine(hwbp_patch_stop_machine_cb, &set, cpu_online_mask);
	if (ret) {
		return ret;
	}
	return set.ret;
}

static int hwbp_write_code_words(void *addr, u32 *insns, int count)
{
	int i;
	void *addrs[HWBP_HOOK_TRAMP_INSN_COUNT];

	if (count > HWBP_HOOK_TRAMP_INSN_COUNT) {
		return -EINVAL;
	}
	for (i = 0; i < count; i++) {
		addrs[i] = (u32 *)addr + i;
	}
	return hwbp_patch_text(addrs, insns, count);
}

static int hwbp_inline_hook_prepare(struct hwbp_inline_hook *hook, void *target,
	void *replace, void *slot)
{
	int i;

	if (!hook || !target || !replace || !slot) {
		return -EINVAL;
	}

	memset(hook, 0, sizeof(*hook));
	hook->target = target;
	hook->replace = replace;
	hook->trampoline_slot = slot;

	for (i = 0; i < HWBP_HOOK_PATCH_INSN_COUNT; i++) {
		hook->original[i] = READ_ONCE(*((u32 *)target + i));
		if (hwbp_a64_is_pc_relative_or_branch(hook->original[i])) {
			return -EOPNOTSUPP;
		}
		hook->trampoline[i] = hook->original[i];
	}

	hwbp_a64_abs_branch(&hook->trampoline[HWBP_HOOK_PATCH_INSN_COUNT],
		(unsigned long)target + HWBP_HOOK_PATCH_INSN_COUNT * sizeof(u32));
	for (i = HWBP_HOOK_PATCH_INSN_COUNT + HWBP_HOOK_PATCH_INSN_COUNT;
	     i < HWBP_HOOK_TRAMP_INSN_COUNT; i++) {
		hook->trampoline[i] = HWBP_A64_NOP;
	}
	hwbp_a64_abs_branch(hook->patch, (unsigned long)replace);
	return 0;
}

static int hwbp_inline_hook_install(struct hwbp_inline_hook *hook)
{
	int ret;

	if (!hook || hook->installed) {
		return -EINVAL;
	}

	ret = hwbp_write_code_words(hook->trampoline_slot, hook->trampoline,
		HWBP_HOOK_TRAMP_INSN_COUNT);
	if (ret) {
		return ret;
	}

	ret = hwbp_write_code_words(hook->target, hook->patch,
		HWBP_HOOK_PATCH_INSN_COUNT);
	if (ret) {
		return ret;
	}

	hook->installed = true;
	return 0;
}

static int hwbp_inline_hook_uninstall(struct hwbp_inline_hook *hook)
{
	int ret;

	if (!hook || !hook->installed) {
		return 0;
	}

	ret = hwbp_write_code_words(hook->target, hook->original,
		HWBP_HOOK_PATCH_INSN_COUNT);
	if (!ret) {
		hook->installed = false;
	}
	return ret;
}

#endif
