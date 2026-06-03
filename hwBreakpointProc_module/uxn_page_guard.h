#ifndef _UXN_PAGE_GUARD_H_
#define _UXN_PAGE_GUARD_H_

#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/esr.h>
#include <asm/debug-monitors.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include "api_proxy.h"

#define HWBP_GUARD_HASH_BITS 8
#define HWBP_GUARD_MISS_WINDOW HZ
#define HWBP_GUARD_MISS_LIMIT 4096UL

struct hwbp_page_bucket {
	struct hlist_node hash_node;
	struct mm_struct *mm;
	unsigned long page_addr;
	struct list_head handles;
	unsigned int active_count;
	unsigned int step_pending_count;
	unsigned int pagemap_readers;
	bool exec_unlocked;
	unsigned long miss_count;
	unsigned long miss_window;
};

struct hwbp_pending_step {
	struct hlist_node hash_node;
	struct list_head cleanup_node;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long page_addr;
	bool had_external_step;
};

static DEFINE_HASHTABLE(g_hwbp_guard_pages, HWBP_GUARD_HASH_BITS);
static DEFINE_HASHTABLE(g_hwbp_pending_steps, HWBP_GUARD_HASH_BITS);
static DEFINE_SPINLOCK(g_hwbp_guard_lock);

static u32 hwbp_guard_hash_key(struct mm_struct *mm, unsigned long page_addr)
{
	return hash_ptr(mm, HWBP_GUARD_HASH_BITS) ^ hash_long(page_addr >> PAGE_SHIFT,
		HWBP_GUARD_HASH_BITS);
}

static pmd_t *hwbp_guard_lookup_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (!mm) {
		return NULL;
	}

	pgd = pgd_offset(mm, addr);
	if (!pgd || pgd_none(READ_ONCE(*pgd)) || pgd_bad(READ_ONCE(*pgd))) {
		return NULL;
	}
	p4d = p4d_offset(pgd, addr);
	if (!p4d || p4d_none(READ_ONCE(*p4d)) || p4d_bad(READ_ONCE(*p4d))) {
		return NULL;
	}
	pud = pud_offset(p4d, addr);
	if (!pud || pud_none(READ_ONCE(*pud)) || pud_bad(READ_ONCE(*pud)) ||
	    pud_sect(READ_ONCE(*pud))) {
		return NULL;
	}
	pmd = pmd_offset(pud, addr);
	if (!pmd || pmd_none(READ_ONCE(*pmd)) || pmd_bad(READ_ONCE(*pmd)) ||
	    pmd_sect(READ_ONCE(*pmd)) || pmd_trans_unstable(pmd)) {
		return NULL;
	}
	return pmd;
}

static bool hwbp_guard_page_is_user_exec(struct mm_struct *mm, unsigned long addr)
{
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;
	spinlock_t *ptl;
	bool executable = false;

	pmd = hwbp_guard_lookup_pmd(mm, addr);
	if (!pmd) {
		return false;
	}

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep) {
		return false;
	}
	pte = READ_ONCE(*ptep);
	executable = pte_present(pte) && pte_user_exec(pte);
	pte_unmap_unlock(ptep, ptl);
	return executable;
}

static void hwbp_guard_flush_tlb_page(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct vma = {
		.vm_mm = mm,
	};

	flush_tlb_page(&vma, addr);
}

static bool hwbp_guard_set_bucket_exec(struct hwbp_page_bucket *bucket, bool executable)
{
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;
	pte_t new_pte;
	spinlock_t *ptl;
	bool changed = false;

	if (!bucket || !bucket->mm) {
		return false;
	}

	pmd = hwbp_guard_lookup_pmd(bucket->mm, bucket->page_addr);
	if (!pmd) {
		return false;
	}

	ptep = pte_offset_map_lock(bucket->mm, pmd, bucket->page_addr, &ptl);
	if (!ptep) {
		return false;
	}

	pte = READ_ONCE(*ptep);
	if (!pte_present(pte)) {
		pte_unmap_unlock(ptep, ptl);
		return false;
	}

	if (executable) {
		new_pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
	} else {
		new_pte = set_pte_bit(pte, __pgprot(PTE_UXN));
	}

	if (!pte_same(pte, new_pte)) {
		set_pte_at(bucket->mm, bucket->page_addr, ptep, new_pte);
		changed = true;
	}
	pte_unmap_unlock(ptep, ptl);
	if (changed) {
		hwbp_guard_flush_tlb_page(bucket->mm, bucket->page_addr);
	}
	bucket->exec_unlocked = executable;
	return true;
}

static struct hwbp_page_bucket *hwbp_guard_find_bucket_locked(struct mm_struct *mm,
	unsigned long page_addr)
{
	struct hwbp_page_bucket *bucket;
	u32 key = hwbp_guard_hash_key(mm, page_addr);

	hash_for_each_possible(g_hwbp_guard_pages, bucket, hash_node, key) {
		if (bucket->mm == mm && bucket->page_addr == page_addr) {
			return bucket;
		}
	}
	return NULL;
}

static struct hwbp_pending_step *hwbp_guard_find_pending_locked(struct task_struct *task)
{
	struct hwbp_pending_step *pending;

	hash_for_each_possible(g_hwbp_pending_steps, pending, hash_node,
		(unsigned long)task) {
		if (pending->task == task) {
			return pending;
		}
	}
	return NULL;
}

static bool hwbp_guard_bucket_has_active_locked(struct hwbp_page_bucket *bucket)
{
	struct HWBP_HANDLE_INFO *info;

	list_for_each_entry(info, &bucket->handles, page_node) {
		if (!info->suspended && !info->auto_released) {
			return true;
		}
	}
	return false;
}

static void hwbp_guard_refresh_active_locked(struct hwbp_page_bucket *bucket)
{
	struct HWBP_HANDLE_INFO *info;
	unsigned int active = 0;

	list_for_each_entry(info, &bucket->handles, page_node) {
		if (!info->suspended && !info->auto_released) {
			active++;
		}
	}
	bucket->active_count = active;
}

static void hwbp_guard_auto_release_bucket_locked(struct hwbp_page_bucket *bucket)
{
	struct HWBP_HANDLE_INFO *info;

	list_for_each_entry(info, &bucket->handles, page_node) {
		info->auto_released = true;
	}
	bucket->active_count = 0;
	hwbp_guard_set_bucket_exec(bucket, true);
}

static bool hwbp_guard_miss_allowed_locked(struct hwbp_page_bucket *bucket)
{
	unsigned long now = jiffies;

	if (time_after(now, bucket->miss_window + HWBP_GUARD_MISS_WINDOW)) {
		bucket->miss_window = now;
		bucket->miss_count = 0;
	}

	bucket->miss_count++;
	if (bucket->miss_count > HWBP_GUARD_MISS_LIMIT) {
		hwbp_guard_auto_release_bucket_locked(bucket);
		return false;
	}
	return true;
}

static bool hwbp_guard_prepare_step_locked(struct hwbp_page_bucket *bucket,
	struct task_struct *task)
{
	struct hwbp_pending_step *pending;

	pending = hwbp_guard_find_pending_locked(task);
	if (pending) {
		return true;
	}

	pending = kzalloc(sizeof(*pending), GFP_ATOMIC);
	if (!pending) {
		return false;
	}

	if (!hwbp_guard_set_bucket_exec(bucket, true)) {
		kfree(pending);
		return false;
	}

	bucket->step_pending_count++;
	INIT_LIST_HEAD(&pending->cleanup_node);
	pending->task = task;
	pending->mm = bucket->mm;
	pending->page_addr = bucket->page_addr;
	pending->had_external_step = test_tsk_thread_flag(task, TIF_SINGLESTEP);
	get_task_struct(task);
	mmgrab(pending->mm);
	hash_add(g_hwbp_pending_steps, &pending->hash_node, (unsigned long)task);
	user_enable_single_step_sym(task);
	return true;
}

static int hwbp_guard_install(struct HWBP_HANDLE_INFO *info, struct task_struct *task,
	unsigned long hook_addr)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct hwbp_page_bucket *bucket;
	struct hwbp_page_bucket *new_bucket = NULL;
	unsigned long flags;
	unsigned long page_addr = hook_addr & PAGE_MASK;
	int ret = 0;

	if (!info || !task || !hook_addr) {
		return -EINVAL;
	}

	mm = get_task_mm(task);
	if (!mm) {
		return -ESRCH;
	}

	mmap_read_lock(mm);
	vma = find_vma(mm, hook_addr);
	if (!vma || hook_addr < vma->vm_start || !(vma->vm_flags & VM_EXEC)) {
		ret = -EACCES;
		goto out_unlock_mmap;
	}

	if (!hwbp_guard_page_is_user_exec(mm, page_addr)) {
		ret = -EACCES;
		goto out_unlock_mmap;
	}

	new_bucket = kzalloc(sizeof(*new_bucket), GFP_KERNEL);
	if (!new_bucket) {
		ret = -ENOMEM;
		goto out_unlock_mmap;
	}
	INIT_LIST_HEAD(&new_bucket->handles);

	info->task = task;
	get_task_struct(task);
	info->mm = mm;
	info->hook_addr = hook_addr;
	info->page_addr = page_addr;
	info->suspended = false;
	info->auto_released = false;
	atomic_set(&info->active_handlers, 0);
	INIT_LIST_HEAD(&info->page_node);

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	bucket = hwbp_guard_find_bucket_locked(mm, page_addr);
	if (!bucket) {
		bucket = new_bucket;
		new_bucket = NULL;
		bucket->mm = mm;
		bucket->page_addr = page_addr;
		bucket->exec_unlocked = true;
		bucket->miss_window = jiffies;
		hash_add(g_hwbp_guard_pages, &bucket->hash_node,
			hwbp_guard_hash_key(mm, page_addr));
	}
	list_add_tail(&info->page_node, &bucket->handles);
	info->page_bucket = bucket;
	hwbp_guard_refresh_active_locked(bucket);
	if (bucket->active_count) {
		hwbp_guard_set_bucket_exec(bucket, false);
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);

out_unlock_mmap:
	mmap_read_unlock(mm);
	if (new_bucket) {
		kfree(new_bucket);
	}
	if (ret) {
		mmput(mm);
	}
	return ret;
}

static void hwbp_guard_uninstall(struct HWBP_HANDLE_INFO *info)
{
	struct hwbp_page_bucket *bucket;
	unsigned long flags;

	if (!info) {
		return;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	bucket = info->page_bucket;
	if (bucket && !list_empty(&info->page_node)) {
		list_del_init(&info->page_node);
		info->page_bucket = NULL;
		hwbp_guard_refresh_active_locked(bucket);
		if (!bucket->active_count) {
			hwbp_guard_set_bucket_exec(bucket, true);
		}
		if (list_empty(&bucket->handles)) {
			hash_del(&bucket->hash_node);
			spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
			kfree(bucket);
			goto release_refs;
		}
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);

release_refs:
	while (atomic_read(&info->active_handlers)) {
		cond_resched();
	}
	if (info->task) {
		put_task_struct(info->task);
		info->task = NULL;
	}
	if (info->mm) {
		mmput(info->mm);
		info->mm = NULL;
	}
}

static int hwbp_guard_suspend(struct HWBP_HANDLE_INFO *info)
{
	struct hwbp_page_bucket *bucket;
	unsigned long flags;

	if (!info || !info->page_bucket) {
		return -EINVAL;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	info->suspended = true;
	bucket = info->page_bucket;
	hwbp_guard_refresh_active_locked(bucket);
	if (!bucket->active_count) {
		hwbp_guard_set_bucket_exec(bucket, true);
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
	return 0;
}

static int hwbp_guard_resume(struct HWBP_HANDLE_INFO *info)
{
	struct hwbp_page_bucket *bucket;
	unsigned long flags;

	if (!info || !info->page_bucket || info->auto_released) {
		return -EINVAL;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	info->suspended = false;
	bucket = info->page_bucket;
	hwbp_guard_refresh_active_locked(bucket);
	if (bucket->active_count) {
		hwbp_guard_set_bucket_exec(bucket, false);
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
	return 0;
}

static bool hwbp_guard_handle_mem_abort(unsigned long far, unsigned long esr,
	struct pt_regs *regs)
{
	struct hwbp_page_bucket *bucket;
	struct HWBP_HANDLE_INFO *info;
	struct HWBP_HANDLE_INFO **hit_infos = NULL;
	struct mm_struct *mm;
	unsigned long page_addr;
	unsigned long guard_page_addr = 0;
	unsigned long pc;
	unsigned long flags;
	unsigned int hit_count = 0;
	unsigned int i;
	bool hit = false;
	bool handled = false;

	if (!regs || !user_mode(regs) ||
	    ESR_ELx_EC(esr) != ESR_ELx_EC_IABT_LOW ||
	    !current->mm) {
		return false;
	}

	pc = instruction_pointer(regs);
	page_addr = pc & PAGE_MASK;
	mm = current->mm;

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	bucket = hwbp_guard_find_bucket_locked(mm, page_addr);
	if (!bucket || !bucket->active_count) {
		spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
		return false;
	}
	guard_page_addr = bucket->page_addr;

	list_for_each_entry(info, &bucket->handles, page_node) {
		if (info->suspended || info->auto_released) {
			continue;
		}
		if (info->hook_addr == pc) {
			hit = true;
			hit_count++;
		}
	}

	if (hit_count) {
		i = 0;
		hit_infos = kmalloc_array(hit_count, sizeof(*hit_infos), GFP_ATOMIC);
		if (!hit_infos) {
			hwbp_guard_auto_release_bucket_locked(bucket);
			spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
			return true;
		}
		list_for_each_entry(info, &bucket->handles, page_node) {
			if (info->suspended || info->auto_released ||
			    info->hook_addr != pc) {
				continue;
			}
			atomic_inc(&info->active_handlers);
			hit_infos[i++] = info;
		}
		hit_count = i;
	}

	if (!hit && !hwbp_guard_miss_allowed_locked(bucket)) {
		spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
		return true;
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);

	for (i = 0; i < hit_count; i++) {
		hwbp_on_guard_hit(hit_infos[i], regs, pc);
		atomic_dec(&hit_infos[i]->active_handlers);
	}
	kfree(hit_infos);

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	page_addr = instruction_pointer(regs) & PAGE_MASK;
	if (page_addr == guard_page_addr) {
		bucket = hwbp_guard_find_bucket_locked(mm, guard_page_addr);
		if (bucket && hwbp_guard_bucket_has_active_locked(bucket)) {
			handled = hwbp_guard_prepare_step_locked(bucket, current);
			if (!handled) {
				hwbp_guard_auto_release_bucket_locked(bucket);
				handled = true;
			}
		} else {
			handled = true;
		}
	} else {
		handled = true;
	}

	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
	return handled;
}

static bool hwbp_guard_handle_debug_exception(unsigned long addr_if_watchpoint,
	unsigned long esr, struct pt_regs *regs)
{
	struct hwbp_pending_step *pending;
	struct hwbp_page_bucket *bucket;
	struct task_struct *pending_task;
	struct mm_struct *pending_mm;
	unsigned long flags;
	bool call_origin = false;

	if (!regs || !user_mode(regs) ||
	    ESR_ELx_EC(esr) != ESR_ELx_EC_SOFTSTP_LOW) {
		return false;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	pending = hwbp_guard_find_pending_locked(current);
	if (!pending) {
		spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
		return false;
	}

	hash_del(&pending->hash_node);
	pending_task = pending->task;
	pending_mm = pending->mm;
	bucket = hwbp_guard_find_bucket_locked(pending->mm, pending->page_addr);
	if (bucket && bucket->step_pending_count) {
		bucket->step_pending_count--;
	}
	if (bucket && bucket->active_count && !bucket->step_pending_count &&
	    !bucket->pagemap_readers) {
		hwbp_guard_set_bucket_exec(bucket, false);
	}
	call_origin = pending->had_external_step;
	kfree(pending);
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);

	if (!call_origin) {
		regs->pstate &= ~DBG_SPSR_SS;
		user_disable_single_step_sym(current);
		put_task_struct(pending_task);
		mmdrop(pending_mm);
		return true;
	}
	put_task_struct(pending_task);
	mmdrop(pending_mm);
	return false;
}

static void hwbp_guard_pagemap_begin(struct mm_struct *mm)
{
	struct hwbp_page_bucket *bucket;
	unsigned long flags;
	int bkt;

	if (!mm) {
		return;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	hash_for_each(g_hwbp_guard_pages, bkt, bucket, hash_node) {
		if (bucket->mm == mm && bucket->active_count) {
			bucket->pagemap_readers++;
			if (bucket->pagemap_readers == 1 && !bucket->exec_unlocked) {
				hwbp_guard_set_bucket_exec(bucket, true);
			}
		}
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
}

static void hwbp_guard_pagemap_end(struct mm_struct *mm)
{
	struct hwbp_page_bucket *bucket;
	unsigned long flags;
	int bkt;

	if (!mm) {
		return;
	}

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	hash_for_each(g_hwbp_guard_pages, bkt, bucket, hash_node) {
		if (bucket->mm == mm && bucket->pagemap_readers) {
			bucket->pagemap_readers--;
			if (!bucket->pagemap_readers && !bucket->step_pending_count &&
			    bucket->active_count && bucket->exec_unlocked) {
				hwbp_guard_set_bucket_exec(bucket, false);
			}
		}
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);
}

static void hwbp_guard_cleanup_all(void)
{
	struct hwbp_page_bucket *bucket;
	struct hlist_node *bucket_tmp;
	struct hwbp_pending_step *pending;
	struct hlist_node *pending_tmp;
	struct hwbp_pending_step *pending_next;
	LIST_HEAD(pending_free);
	unsigned long flags;
	int bkt;

	spin_lock_irqsave(&g_hwbp_guard_lock, flags);
	hash_for_each_safe(g_hwbp_pending_steps, bkt, pending_tmp, pending, hash_node) {
		hash_del(&pending->hash_node);
		list_add_tail(&pending->cleanup_node, &pending_free);
	}
	hash_for_each_safe(g_hwbp_guard_pages, bkt, bucket_tmp, bucket, hash_node) {
		hwbp_guard_set_bucket_exec(bucket, true);
		hash_del(&bucket->hash_node);
		kfree(bucket);
	}
	spin_unlock_irqrestore(&g_hwbp_guard_lock, flags);

	list_for_each_entry_safe(pending, pending_next, &pending_free, cleanup_node) {
		list_del_init(&pending->cleanup_node);
		if (!pending->had_external_step) {
			user_disable_single_step_sym(pending->task);
		}
		put_task_struct(pending->task);
		mmdrop(pending->mm);
		kfree(pending);
	}
}

#endif
