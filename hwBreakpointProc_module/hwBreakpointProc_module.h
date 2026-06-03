#ifndef _HWBP_PROC_H_
#define _HWBP_PROC_H_
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/compat.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/hw_breakpoint.h>
#include <linux/ksm.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/pid.h>
#include <linux/slab.h> //kmalloc与kfree
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include "ver_control.h"
#include "arm64_register_helper.h"
#include "cvector.h"
#ifdef CONFIG_USE_PROC_FILE_NODE
#include <linux/proc_fs.h>
#include "hide_procfs_dir.h"
#endif
//////////////////////////////////////////////////////////////////

enum {
	CMD_OPEN_PROCESS, 				// 打开进程
	CMD_CLOSE_PROCESS, 				// 关闭进程
	CMD_GET_NUM_BRPS, 				// 获取CPU硬件执行断点支持数量
	CMD_GET_NUM_WRPS, 				// 获取CPU硬件访问断点支持数量
	CMD_INST_PROCESS_HWBP,			// 安装进程硬件断点
	CMD_UNINST_PROCESS_HWBP,		// 卸载进程硬件断点
	CMD_SUSPEND_PROCESS_HWBP,		// 暂停进程硬件断点
	CMD_RESUME_PROCESS_HWBP,		// 恢复进程硬件断点
	CMD_GET_HWBP_HIT_COUNT,			// 获取硬件断点命中地址数量
	CMD_GET_HWBP_HIT_DETAIL,		// 获取硬件断点命中详细信息
	CMD_SET_HOOK_PC,				// 设置无条件Hook跳转
	CMD_HIDE_KERNEL_MODULE,			// 隐藏驱动
};

struct hwBreakpointProcDev {
#ifdef CONFIG_USE_PROC_FILE_NODE
	struct proc_dir_entry *proc_parent;
	struct proc_dir_entry *proc_entry;
#endif
	bool is_hidden_module; //是否已经隐藏过驱动列表了
};
static struct hwBreakpointProcDev *g_hwBreakpointProc_devp;

static ssize_t hwBreakpointProc_read(struct file* filp, char __user* buf, size_t size, loff_t* ppos);
static int hwBreakpointProc_release(struct inode *inode, struct file *filp);
static const struct proc_ops hwBreakpointProc_proc_ops = {
    .proc_read    = hwBreakpointProc_read,
	.proc_release = hwBreakpointProc_release,
};

#pragma pack(1)
struct my_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
};
struct HWBP_HIT_ITEM {
	uint64_t task_id;
	uint64_t hit_addr;
	uint64_t hit_time;
	struct my_user_pt_regs regs_info;
};

enum HWBP_HIT_REG_TYPE {
	HWBP_HIT_REG_NONE = 0,
	HWBP_HIT_REG_X = 1,
	HWBP_HIT_REG_W = 2,
	HWBP_HIT_REG_SP = 3,
	HWBP_HIT_REG_PC = 4,
	HWBP_HIT_REG_S = 5,
	HWBP_HIT_REG_PSTATE_NZCV = 6,
};

#define HWBP_HIT_REG_WRITE_FLAG_SKIP_INSN 0x1U
#define HWBP_PSTATE_NZCV_N 0x8U
#define HWBP_PSTATE_NZCV_Z 0x4U
#define HWBP_PSTATE_NZCV_C 0x2U
#define HWBP_PSTATE_NZCV_V 0x1U
#define HWBP_PSTATE_NZCV_EQ (HWBP_PSTATE_NZCV_Z | HWBP_PSTATE_NZCV_C)

struct HWBP_HIT_REG_WRITE_RULE {
	uint8_t enabled;
	uint8_t reg_type;
	uint8_t reg_index;
	uint8_t flags;
	uint64_t value;
};

struct HWBP_INSTALL_EX_CONFIG {
	uint64_t bp_handle;
	uint32_t magic;
	uint16_t version;
	uint16_t size;
	struct HWBP_HIT_REG_WRITE_RULE hit_write;
};
#pragma pack()

#define HWBP_INSTALL_EX_MAGIC 0x48574558U
#define HWBP_INSTALL_EX_VERSION 2U
#define HWBP_INSTALL_FLAG_HIT_REG_WRITE (1ULL << 16)

struct HWBP_HANDLE_INFO {
	uint64_t task_id;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long hook_addr;
	unsigned long page_addr;
	void *page_bucket;
	bool is_32bit_task;
	bool suspended;
	bool auto_released;
	struct HWBP_HIT_REG_WRITE_RULE hit_write;
	size_t hit_total_count;
	cvector hit_item_arr;
	struct list_head page_node;
	atomic_t active_handlers;
	spinlock_t hit_lock;
};

#endif /* _HWBP_PROC_H_ */
