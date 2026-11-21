#ifndef _ANTI_PERF_DETECTION_H_
#define _ANTI_PERF_DETECTION_H_
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <asm/ptrace.h>

/*
 * perf_event_open 路径的防御（对应文档 5.2 节“主动触发测试 / 第 5 步”）。
 *
 * 原理说明：
 *   - 反作弊用 perf_event_open 创建一个 HW breakpoint 事件（type=PERF_TYPE_BREAKPOINT），
 *     然后主动调用一个 demo 函数，看断点是否正常触发、寄存器是否被正确修改。
 *   - 文档给出的正确防御是“一律放行”：我们的硬件断点精确到 TID + 目标地址，
 *     只要反作弊测试的不是我们 Hook 的那个具体业务函数，perf_event_open 在内核底层
 *     依然正常处理，物理异常正常触发。我们只拦截自己关心的目标。
 *   - 本文件新增一个 __arm64_sys_perf_event_open 的 kprobe，仅做断点事件识别与
 *     日志输出（awareness），绝不改写返回值，从而保证“放行”语义。
 *
 * 注意：
 *   - 本 kprobe 只拦截用户态发起的 perf_event_open syscall，绝不会拦截本模块
 *     自己通过 register_user_hw_breakpoint() 走的内部路径（那条路不经 syscall），
 *     因此与自身断点零冲突。
 */

#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
#endif

struct hook_perf_data {
    int  is_breakpoint;
    pid_t pid;
    int  cpu;
};

/*
 * __arm64_sys_perf_event_open 的 arm64 入口签名：
 *   asmlinkage long __arm64_sys_perf_event_open(const struct pt_regs *regs);
 * kprobe 的 regs->regs[0] 是指向真实 syscall 参数的 pt_regs 指针：
 *   syscall_regs->regs[0] = perf_event_attr __user *attr_uptr
 *   syscall_regs->regs[1] = pid_t pid
 *   syscall_regs->regs[2] = int cpu
 */
static int entry_perf_open_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs->regs[0];
    struct perf_event_attr __user *attr_uptr;
    struct perf_event_attr attr;
    pid_t pid;
    int cpu;

    if (!syscall_regs)
        return 0;

    attr_uptr = (struct perf_event_attr __user *)syscall_regs->regs[0];
    pid = (pid_t)syscall_regs->regs[1];
    cpu = (int)syscall_regs->regs[2];

    if (!attr_uptr)
        return 0;

    if (x_copy_from_user(&attr, attr_uptr, sizeof(attr)) != 0)
        return 0;

    if (attr.type == PERF_TYPE_BREAKPOINT) {
        printk_debug(KERN_INFO
                     "[anti_perf] breakpoint perf_event_open: pid=%d cpu=%d "
                     "bp_addr=0x%llx bp_len=0x%llx bp_type=0x%x\n",
                     pid, cpu,
                     (unsigned long long)attr.bp_addr,
                     (unsigned long long)attr.bp_len,
                     attr.bp_type);
    }

    /* 一律放行：不改返回值，让原始 syscall 正常执行 */
    return 0;
}

static struct kprobe kp_perf_open = {
    .symbol_name = "__arm64_sys_perf_event_open",
    .pre_handler = entry_perf_open_handler,
};

static bool start_anti_perf_detection(void)
{
    int ret;

    ret = register_kprobe(&kp_perf_open);
    if (ret < 0) {
        printk_debug(KERN_INFO "register_kprobe(__arm64_sys_perf_event_open) failed: %d\n", ret);
        return false;
    }
    printk_debug(KERN_INFO "kprobe at %s registered, addr: %lx\n",
                 kp_perf_open.symbol_name, kp_perf_open.addr);
    return true;
}

static void stop_anti_perf_detection(void)
{
    if (kp_perf_open.addr) {
        unregister_kprobe(&kp_perf_open);
        printk_debug(KERN_INFO "kprobe __arm64_sys_perf_event_open unregistered\n");
    }
}

#endif /* _ANTI_PERF_DETECTION_H_ */
