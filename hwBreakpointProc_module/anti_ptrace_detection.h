#ifndef _ANTI_PTRACE_DETECTION_H_
#define _ANTI_PTRACE_DETECTION_H_
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include "arm64_register_helper.h"

#define PTRACE_GETREGSET   0x4204
#define PTRACE_SETREGSET   0x4205
#define NT_ARM_HW_BREAK	0x402		/* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH	0x403		/* ARM hardware watchpoint registers */

/* ------------------------------------------------------------------ */
/* 虚假调试寄存器账本（对应文档 5.2 节“假账本 / State Spoofing”）      */
/* ------------------------------------------------------------------ */
struct fake_hw_reg {
    uint64_t addr;
    uint32_t ctrl;
    uint32_t pad;
};

/* 每个被 ptrace 探查的目标线程各持有一份账本，key = TID */
struct fake_hw_ledger {
    struct list_head list;
    pid_t tid;
    struct fake_hw_reg break_regs[16];
    int break_count;
    struct fake_hw_reg watch_regs[16];
    int watch_count;
};

static LIST_HEAD(g_fake_ledger_list);
static DEFINE_SPINLOCK(g_fake_ledger_lock);

static struct fake_hw_ledger *find_or_create_fake_ledger(pid_t tid) {
    struct fake_hw_ledger *ledger;
    unsigned long flags;

    spin_lock_irqsave(&g_fake_ledger_lock, flags);
    list_for_each_entry(ledger, &g_fake_ledger_list, list) {
        if (ledger->tid == tid) {
            spin_unlock_irqrestore(&g_fake_ledger_lock, flags);
            return ledger;
        }
    }
    spin_unlock_irqrestore(&g_fake_ledger_lock, flags);

    /* kretprobe 处理器运行于原子上下文，必须用 GFP_ATOMIC */
    ledger = kzalloc(sizeof(*ledger), GFP_ATOMIC);
    if (!ledger)
        return NULL;
    ledger->tid = tid;
    INIT_LIST_HEAD(&ledger->list);

    spin_lock_irqsave(&g_fake_ledger_lock, flags);
    list_add_tail(&ledger->list, &g_fake_ledger_list);
    spin_unlock_irqrestore(&g_fake_ledger_lock, flags);
    return ledger;
}

struct hook_ptrace_data {
    struct iovec iov;
    long request;
    unsigned long addr;      /* NT_ARM_HW_BREAK / NT_ARM_HW_WATCH */
    pid_t target_tid;        /* 被探查的目标线程 TID */
};

static int entry_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_ptrace_data *data = (struct hook_ptrace_data *)ri->data;
    /* arch_ptrace(child, request, addr, data)：参数直接映射到 x0-x3 */
    struct task_struct *child = (struct task_struct *)regs->regs[0];

    data->request = (long)regs->regs[1];
    data->addr = (unsigned long)regs->regs[2];
    data->target_tid = 0;
    data->iov.iov_base = NULL;
    data->iov.iov_len = 0;

    if (child)
        data->target_tid = task_pid_nr(child);

    if ((data->request == PTRACE_GETREGSET || data->request == PTRACE_SETREGSET) &&
        (data->addr == NT_ARM_HW_WATCH || data->addr == NT_ARM_HW_BREAK)) {
        unsigned long iov_user_ptr = regs->regs[3];
        if (iov_user_ptr &&
            x_copy_from_user(&data->iov, (struct iovec __user *)iov_user_ptr, sizeof(struct iovec)) != 0) {
            data->iov.iov_base = NULL;
            data->iov.iov_len = 0;
        }
    }
    return 0;
}

static int ret_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct hook_ptrace_data *data = (struct hook_ptrace_data *)ri->data;
    struct fake_hw_ledger *ledger;
    struct user_hwdebug_state hw_state;
    struct fake_hw_reg *ledger_regs;
    int *ledger_count;
    int is_break, max_count;
    size_t copy_size;
    int i;

    if (data->addr != NT_ARM_HW_BREAK && data->addr != NT_ARM_HW_WATCH)
        return 0;

    if (!data->iov.iov_base || !data->iov.iov_len)
        return 0;

    if (!access_ok((void __user *)data->iov.iov_base, data->iov.iov_len))
        return 0;

    is_break  = (data->addr == NT_ARM_HW_BREAK);
    max_count = is_break ? getCpuNumBrps() : getCpuNumWrps();

    ledger = find_or_create_fake_ledger(data->target_tid);
    if (!ledger)
        return 0;

    ledger_regs  = is_break ? ledger->break_regs : ledger->watch_regs;
    ledger_count = is_break ? &ledger->break_count : &ledger->watch_count;

    copy_size = min(data->iov.iov_len, sizeof(hw_state));

    /* ----------------------------------------------------------- */
    /* 戏码 A：反作弊写寄存器 (PTRACE_SETREGSET)                   */
    /*   → 存进假账本，绝不写回真实物理寄存器；                    */
    /*   → 越界诱导陷阱（设 Max+1 个）返回 -ENOSPC 完美模拟内核。  */
    /* ----------------------------------------------------------- */
    if (data->request == PTRACE_SETREGSET) {
        int requested = 0;

        memset(&hw_state, 0, sizeof(hw_state));
        if (x_copy_from_user(&hw_state, (void __user *)data->iov.iov_base, copy_size) != 0)
            return 0;

        /* 统计用户试图设置的非零断点数 */
        for (i = 0; i < 16; i++) {
            if (hw_state.dbg_regs[i].addr != 0)
                requested++;
        }

        /* 越界诱导陷阱：多于物理上限 → 模拟设备空间不足 */
        if (requested > max_count) {
            regs_set_return_value(regs, -ENOSPC);
            return 0;
        }

        /* 写假账本（读写一致性闭环全程只与账本交互） */
        for (i = 0; i < 16; i++) {
            ledger_regs[i].addr = hw_state.dbg_regs[i].addr;
            ledger_regs[i].ctrl = hw_state.dbg_regs[i].ctrl;
        }
        *ledger_count = requested;
        regs_set_return_value(regs, 0);
        return 0;
    }

    /* ----------------------------------------------------------- */
    /* 戏码 B：反作弊读寄存器 (PTRACE_GETREGSET)                   */
    /*   → 从假账本构造返回数据，物理寄存器绝不暴露。              */
    /* ----------------------------------------------------------- */
    if (data->request == PTRACE_GETREGSET) {
        memset(&hw_state, 0, sizeof(hw_state));
        hw_state.dbg_info = (uint32_t)max_count;

        for (i = 0; i < *ledger_count && i < max_count && i < 16; i++) {
            hw_state.dbg_regs[i].addr = ledger_regs[i].addr;
            hw_state.dbg_regs[i].ctrl = ledger_regs[i].ctrl;
        }

        if (x_copy_to_user((void __user *)data->iov.iov_base, &hw_state, copy_size) != 0)
            return 0;

        regs_set_return_value(regs, 0);
        return 0;
    }

    return 0;
}


static struct kretprobe kretp_ptrace = {
    .kp.symbol_name    = "arch_ptrace",
    .data_size  = sizeof(struct hook_ptrace_data),
    .entry_handler    = entry_ptrace_handler,
    .handler    = ret_ptrace_handler,
    .maxactive  = 20,
};

static bool start_anti_ptrace_detection(struct mutex *p_hwbp_handle_info_mutex, cvector *p_hwbp_handle_info_arr) {
    int ret = 0;
    if(!p_hwbp_handle_info_mutex || !p_hwbp_handle_info_arr) {
        printk_debug(KERN_INFO "start_anti_ptrace_detection param error\n");
        return false;
    }
    ret = register_kretprobe(&kretp_ptrace);
    if (ret < 0) {
        printk_debug(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
        return false;
    }
    printk_debug(KERN_INFO "kretprobe at %s registered, addr: %lx\n", kretp_ptrace.kp.symbol_name, kretp_ptrace.kp.addr);
	return true;
}


static void stop_anti_ptrace_detection(void) {
    struct fake_hw_ledger *ledger, *tmp;
    unsigned long flags;

    if(kretp_ptrace.kp.addr) {
        unregister_kretprobe(&kretp_ptrace);
        printk_debug(KERN_INFO "kretprobe unregistered\n");
    }

    /* 释放所有虚假账本 */
    spin_lock_irqsave(&g_fake_ledger_lock, flags);
    list_for_each_entry_safe(ledger, tmp, &g_fake_ledger_list, list) {
        list_del(&ledger->list);
        kfree(ledger);
    }
    spin_unlock_irqrestore(&g_fake_ledger_lock, flags);
}

#endif
