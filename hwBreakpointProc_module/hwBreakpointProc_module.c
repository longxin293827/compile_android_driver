#include "hwBreakpointProc_module.h"
#include "proc_pid.h"
#include "api_proxy.h"
#include "fpsimd_action_helper.h"
#include "arm64_inline_hook.h"
#include "pmu_el0_guard.h"

#pragma pack(push,1)
struct ioctl_request {
	char cmd;
	uint64_t param1;
	uint64_t param2;
	uint64_t param3;
	uint64_t buf_size;
};
#pragma pack(pop)

static atomic64_t g_hook_pc;
static struct mutex g_hwbp_handle_info_mutex;
static cvector g_hwbp_handle_info_arr;

static struct hwbp_inline_hook g_do_mem_abort_hook;
static struct hwbp_inline_hook g_do_debug_exception_hook;
static struct hwbp_inline_hook g_pagemap_read_hook;
static hwbp_do_mem_abort_t g_orig_do_mem_abort;
static hwbp_do_debug_exception_t g_orig_do_debug_exception;
static hwbp_pagemap_read_t g_orig_pagemap_read;

static void record_hit_details(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs)
{
	struct HWBP_HIT_ITEM hit_item = {0};

	if (!info || !regs) {
		return;
	}

	hit_item.task_id = info->task_id;
	hit_item.hit_addr = regs->pc;
	hit_item.hit_time = ktime_get_real_seconds();
	memcpy(&hit_item.regs_info.regs, regs->regs, sizeof(hit_item.regs_info.regs));
	hit_item.regs_info.sp = regs->sp;
	hit_item.regs_info.pc = regs->pc;
	hit_item.regs_info.pstate = regs->pstate;
	hit_item.regs_info.orig_x0 = regs->orig_x0;
	hit_item.regs_info.syscallno = regs->syscallno;

	if (info->hit_item_arr && cvector_length(info->hit_item_arr) < MIN_LEN) {
		cvector_pushback(info->hit_item_arr, &hit_item);
	}
}

static bool hwbp_hit_reg_write_rule_valid(struct HWBP_HIT_REG_WRITE_RULE *rule)
{
	if (!rule || !rule->enabled) {
		return true;
	}
	if (rule->flags & ~HWBP_HIT_REG_WRITE_FLAG_SKIP_INSN) {
		return false;
	}

	switch (rule->reg_type) {
	case HWBP_HIT_REG_NONE:
		return true;
	case HWBP_HIT_REG_X:
	case HWBP_HIT_REG_W:
		return rule->reg_index <= 30;
	case HWBP_HIT_REG_SP:
	case HWBP_HIT_REG_PC:
		return rule->reg_index == 0;
	case HWBP_HIT_REG_S:
		return rule->reg_index <= 31;
	case HWBP_HIT_REG_PSTATE_NZCV:
		return rule->reg_index == 0 && (rule->value & ~0xfULL) == 0;
	default:
		return false;
	}
}

static bool hwbp_load_install_ex_config(struct ioctl_request *hdr, char __user *buf,
	struct HWBP_HIT_REG_WRITE_RULE *rule)
{
	struct HWBP_INSTALL_EX_CONFIG config = {0};

	if (!hdr || !buf || !rule) {
		return false;
	}
	if ((hdr->param3 & HWBP_INSTALL_FLAG_HIT_REG_WRITE) == 0) {
		memset(rule, 0, sizeof(*rule));
		return true;
	}
	if (hdr->buf_size < sizeof(config)) {
		return false;
	}
	if (x_copy_from_user(&config, buf, sizeof(config))) {
		return false;
	}
	if (config.magic != HWBP_INSTALL_EX_MAGIC ||
	    config.version != HWBP_INSTALL_EX_VERSION ||
	    config.size != sizeof(config)) {
		return false;
	}
	if (!hwbp_hit_reg_write_rule_valid(&config.hit_write)) {
		return false;
	}

	memcpy(rule, &config.hit_write, sizeof(*rule));
	return true;
}

static bool hwbp_apply_hit_reg_write(struct HWBP_HANDLE_INFO *hwbp_handle_info,
	struct pt_regs *regs, uint64_t hit_pc)
{
	struct HWBP_HIT_REG_WRITE_RULE *rule;
	bool applied = true;
	bool pc_changed = false;

	if (!hwbp_handle_info || !regs) {
		return false;
	}

	rule = &hwbp_handle_info->hit_write;
	if (!rule->enabled) {
		return false;
	}

	switch (rule->reg_type) {
	case HWBP_HIT_REG_NONE:
		break;
	case HWBP_HIT_REG_X:
		if (rule->reg_index <= 30) {
			regs->regs[rule->reg_index] = rule->value;
		}
		break;
	case HWBP_HIT_REG_W:
		if (rule->reg_index <= 30) {
			regs->regs[rule->reg_index] = (uint32_t)rule->value;
		}
		break;
	case HWBP_HIT_REG_SP:
		regs->sp = rule->value;
		break;
	case HWBP_HIT_REG_PC:
		regs->pc = rule->value;
		pc_changed = true;
		break;
	case HWBP_HIT_REG_S:
		applied = hwbp_write_current_s_reg(rule->reg_index, (uint32_t)rule->value);
		break;
	case HWBP_HIT_REG_PSTATE_NZCV:
		hwbp_write_pstate_nzcv(regs, (uint32_t)rule->value);
		break;
	default:
		break;
	}

	if (applied && (rule->flags & HWBP_HIT_REG_WRITE_FLAG_SKIP_INSN)) {
		regs->pc = hit_pc + 4;
		pc_changed = true;
	}

	return applied && pc_changed;
}

static void hwbp_on_guard_hit(struct HWBP_HANDLE_INFO *info, struct pt_regs *regs,
	uint64_t hit_pc)
{
	uint64_t hook_pc;
	unsigned long flags;

	if (!info || !regs) {
		return;
	}

	printk_debug(KERN_INFO "UXN hwbp HIT pc:%px handle:%px\n",
		(void *)hit_pc, info);

	hook_pc = atomic64_read(&g_hook_pc);
	if (hook_pc) {
		regs->pc = hook_pc;
		return;
	}

	hwbp_apply_hit_reg_write(info, regs, hit_pc);

	spin_lock_irqsave(&info->hit_lock, flags);
	info->hit_total_count++;
	record_hit_details(info, regs);
	spin_unlock_irqrestore(&info->hit_lock, flags);
}

#include "uxn_page_guard.h"

static struct HWBP_HANDLE_INFO *hwbp_find_handle_locked(uint64_t handle)
{
	citerator iter;

	if (!g_hwbp_handle_info_arr || !handle) {
		return NULL;
	}

	for (iter = cvector_begin(g_hwbp_handle_info_arr);
	     iter != cvector_end(g_hwbp_handle_info_arr);
	     iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = *(struct HWBP_HANDLE_INFO **)iter;

		if ((uint64_t)info == handle) {
			return info;
		}
	}
	return NULL;
}

static bool hwbp_remove_handle_locked(struct HWBP_HANDLE_INFO *target)
{
	citerator iter;

	if (!g_hwbp_handle_info_arr || !target) {
		return false;
	}

	for (iter = cvector_begin(g_hwbp_handle_info_arr);
	     iter != cvector_end(g_hwbp_handle_info_arr);
	     iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = *(struct HWBP_HANDLE_INFO **)iter;

		if (info == target) {
			cvector_rm(g_hwbp_handle_info_arr, iter);
			return true;
		}
	}
	return false;
}

static void hwbp_free_handle(struct HWBP_HANDLE_INFO *info)
{
	if (!info) {
		return;
	}

	hwbp_guard_uninstall(info);
	if (info->hit_item_arr) {
		cvector_destroy(info->hit_item_arr);
		info->hit_item_arr = NULL;
	}
	kfree(info);
}

static void hwbp_hooked_do_mem_abort(unsigned long far, unsigned long esr,
	struct pt_regs *regs)
{
	if (hwbp_guard_handle_mem_abort(far, esr, regs)) {
		return;
	}
	g_orig_do_mem_abort(far, esr, regs);
}

static void hwbp_hooked_do_debug_exception(unsigned long addr_if_watchpoint,
	unsigned long esr, struct pt_regs *regs)
{
	if (hwbp_guard_handle_debug_exception(addr_if_watchpoint, esr, regs)) {
		return;
	}
	g_orig_do_debug_exception(addr_if_watchpoint, esr, regs);
}

static ssize_t hwbp_hooked_pagemap_read(struct file *file, char __user *buf,
	size_t count, loff_t *ppos)
{
	struct mm_struct *mm = file ? file->private_data : NULL;
	ssize_t ret;

	hwbp_guard_pagemap_begin(mm);
	ret = g_orig_pagemap_read(file, buf, count, ppos);
	hwbp_guard_pagemap_end(mm);
	return ret;
}

static int hwbp_install_inline_hooks(void)
{
	int ret;

	ret = hwbp_inline_hook_prepare(&g_do_mem_abort_hook, do_mem_abort_sym,
		hwbp_hooked_do_mem_abort, hwbp_hook_slot_0);
	if (ret) {
		return ret;
	}
	g_orig_do_mem_abort = (hwbp_do_mem_abort_t)g_do_mem_abort_hook.trampoline_slot;
	ret = hwbp_inline_hook_install(&g_do_mem_abort_hook);
	if (ret) {
		g_orig_do_mem_abort = NULL;
		return ret;
	}

	ret = hwbp_inline_hook_prepare(&g_do_debug_exception_hook, do_debug_exception_sym,
		hwbp_hooked_do_debug_exception, hwbp_hook_slot_1);
	if (ret) {
		goto uninstall_mem_abort;
	}
	g_orig_do_debug_exception =
		(hwbp_do_debug_exception_t)g_do_debug_exception_hook.trampoline_slot;
	ret = hwbp_inline_hook_install(&g_do_debug_exception_hook);
	if (ret) {
		goto uninstall_mem_abort;
	}

	ret = hwbp_inline_hook_prepare(&g_pagemap_read_hook, pagemap_read_sym,
		hwbp_hooked_pagemap_read, hwbp_hook_slot_2);
	if (ret) {
		goto uninstall_debug_exception;
	}
	g_orig_pagemap_read = (hwbp_pagemap_read_t)g_pagemap_read_hook.trampoline_slot;
	ret = hwbp_inline_hook_install(&g_pagemap_read_hook);
	if (ret) {
		goto uninstall_debug_exception;
	}
	return 0;

uninstall_debug_exception:
	g_orig_pagemap_read = NULL;
	hwbp_inline_hook_uninstall(&g_do_debug_exception_hook);
	g_orig_do_debug_exception = NULL;
uninstall_mem_abort:
	hwbp_inline_hook_uninstall(&g_do_mem_abort_hook);
	g_orig_do_mem_abort = NULL;
	return ret;
}

static void hwbp_uninstall_inline_hooks(void)
{
	hwbp_inline_hook_uninstall(&g_pagemap_read_hook);
	hwbp_inline_hook_uninstall(&g_do_debug_exception_hook);
	hwbp_inline_hook_uninstall(&g_do_mem_abort_hook);
	g_orig_pagemap_read = NULL;
	g_orig_do_debug_exception = NULL;
	g_orig_do_mem_abort = NULL;
}

static ssize_t OnCmdOpenProcess(struct ioctl_request *hdr, char __user *buf)
{
	uint64_t pid = hdr->param1;
	uint64_t handle;
	struct pid *proc_pid_struct;

	printk_debug(KERN_INFO "CMD_OPEN_PROCESS\n");

	proc_pid_struct = get_proc_pid_struct(pid);
	if (!proc_pid_struct) {
		return -EINVAL;
	}

	handle = (uint64_t)proc_pid_struct;
	if (x_copy_to_user(buf, &handle, sizeof(handle))) {
		release_proc_pid_struct(proc_pid_struct);
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdCloseProcess(struct ioctl_request *hdr, char __user *buf)
{
	struct pid *proc_pid_struct = (struct pid *)hdr->param1;

	printk_debug(KERN_INFO "CMD_CLOSE_PROCESS\n");
	release_proc_pid_struct(proc_pid_struct);
	return 0;
}

static ssize_t OnCmdGetCpuNumBrps(struct ioctl_request *hdr, char __user *buf)
{
	printk_debug(KERN_INFO "CMD_GET_NUM_BRPS\n");
	return getCpuNumBrps();
}

static ssize_t OnCmdGetCpuNumWrps(struct ioctl_request *hdr, char __user *buf)
{
	printk_debug(KERN_INFO "CMD_GET_NUM_WRPS\n");
	return getCpuNumWrps();
}

static ssize_t OnCmdInstProcessHwbp(struct ioctl_request *hdr, char __user *buf)
{
	struct pid *proc_pid_struct = (struct pid *)hdr->param1;
	uint64_t proc_virt_addr = hdr->param2;
	char hwbp_len = hdr->param3 & 0xff;
	char hwbp_type = (hdr->param3 >> 8) & 0xff;
	struct HWBP_HIT_REG_WRITE_RULE hit_write = {0};
	struct HWBP_HANDLE_INFO *info;
	pid_t pid_val;
	struct task_struct *task;
	uint64_t handle;
	int ret;

	printk_debug(KERN_INFO "CMD_INST_PROCESS_HWBP\n");
	printk_debug(KERN_INFO "proc_virt_addr:%px len:%d type:%d\n",
		(void *)proc_virt_addr, hwbp_len, hwbp_type);

	if (hwbp_type != HW_BREAKPOINT_X) {
		return -EOPNOTSUPP;
	}
	if (!hwbp_load_install_ex_config(hdr, buf, &hit_write)) {
		return -EINVAL;
	}

	pid_val = pid_nr(proc_pid_struct);
	if (!pid_val) {
		return -EINVAL;
	}

	task = pid_task(proc_pid_struct, PIDTYPE_PID);
	if (!task) {
		return -EINVAL;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		return -ENOMEM;
	}

	info->task_id = pid_val;
	info->is_32bit_task = is_compat_thread(task_thread_info(task));
	memcpy(&info->hit_write, &hit_write, sizeof(hit_write));
	INIT_LIST_HEAD(&info->page_node);
	atomic_set(&info->active_handlers, 0);
	spin_lock_init(&info->hit_lock);
	info->hit_item_arr = cvector_create(sizeof(struct HWBP_HIT_ITEM));
	if (!info->hit_item_arr) {
		kfree(info);
		return -ENOMEM;
	}

	ret = hwbp_guard_install(info, task, proc_virt_addr);
	if (ret) {
		hwbp_free_handle(info);
		return ret;
	}

	handle = (uint64_t)info;
	mutex_lock(&g_hwbp_handle_info_mutex);
	ret = cvector_pushback(g_hwbp_handle_info_arr, &info);
	mutex_unlock(&g_hwbp_handle_info_mutex);
	if (ret) {
		hwbp_free_handle(info);
		return -ENOMEM;
	}

	if (x_copy_to_user(buf, &handle, sizeof(handle))) {
		mutex_lock(&g_hwbp_handle_info_mutex);
		hwbp_remove_handle_locked(info);
		mutex_unlock(&g_hwbp_handle_info_mutex);
		hwbp_free_handle(info);
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdUninstProcessHwbp(struct ioctl_request *hdr, char __user *buf)
{
	struct HWBP_HANDLE_INFO *info;

	printk_debug(KERN_INFO "CMD_UNINST_PROCESS_HWBP handle:%px\n",
		(void *)hdr->param1);

	mutex_lock(&g_hwbp_handle_info_mutex);
	info = hwbp_find_handle_locked(hdr->param1);
	if (info) {
		hwbp_remove_handle_locked(info);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);

	if (!info) {
		return -EFAULT;
	}

	hwbp_free_handle(info);
	return 0;
}

static ssize_t OnCmdSuspendProcessHwbp(struct ioctl_request *hdr, char __user *buf)
{
	struct HWBP_HANDLE_INFO *info;
	int ret = -EFAULT;

	printk_debug(KERN_INFO "CMD_SUSPEND_PROCESS_HWBP handle:%px\n",
		(void *)hdr->param1);

	mutex_lock(&g_hwbp_handle_info_mutex);
	info = hwbp_find_handle_locked(hdr->param1);
	if (info) {
		ret = hwbp_guard_suspend(info);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return ret;
}

static ssize_t OnCmdResumeProcessHwbp(struct ioctl_request *hdr, char __user *buf)
{
	struct HWBP_HANDLE_INFO *info;
	int ret = -EFAULT;

	printk_debug(KERN_INFO "CMD_RESUME_PROCESS_HWBP handle:%px\n",
		(void *)hdr->param1);

	mutex_lock(&g_hwbp_handle_info_mutex);
	info = hwbp_find_handle_locked(hdr->param1);
	if (info) {
		ret = hwbp_guard_resume(info);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return ret;
}

static ssize_t OnCmdGetHwbpHitCount(struct ioctl_request *hdr, char __user *buf)
{
#pragma pack(1)
	struct buf_layout {
		uint64_t hit_total_count;
		uint64_t hit_item_arr_count;
	};
#pragma pack()
	struct HWBP_HANDLE_INFO *info;
	struct buf_layout user_data = {0};
	unsigned long flags;

	printk_debug(KERN_INFO "CMD_GET_HWBP_HIT_COUNT handle:%px\n",
		(void *)hdr->param1);

	mutex_lock(&g_hwbp_handle_info_mutex);
	info = hwbp_find_handle_locked(hdr->param1);
	if (info && info->hit_item_arr) {
		spin_lock_irqsave(&info->hit_lock, flags);
		user_data.hit_total_count = info->hit_total_count;
		user_data.hit_item_arr_count = cvector_length(info->hit_item_arr);
		spin_unlock_irqrestore(&info->hit_lock, flags);
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);

	if (x_copy_to_user(buf, &user_data, sizeof(user_data))) {
		return -EINVAL;
	}
	return 0;
}

static ssize_t OnCmdGetHwbpHitDetail(struct ioctl_request *hdr, char __user *buf)
{
	struct HWBP_HANDLE_INFO *info;
	struct HWBP_HIT_ITEM hit_item;
	size_t size = hdr->buf_size;
	size_t copy_pos = (size_t)buf;
	size_t end_pos = copy_pos + size;
	size_t item_count;
	size_t i;
	ssize_t count = 0;
	unsigned long flags;

	printk_debug(KERN_INFO "CMD_GET_HWBP_HIT_DETAIL handle:%px\n",
		(void *)hdr->param1);

	mutex_lock(&g_hwbp_handle_info_mutex);
	info = hwbp_find_handle_locked(hdr->param1);
	if (!info || !info->hit_item_arr) {
		mutex_unlock(&g_hwbp_handle_info_mutex);
		return 0;
	}

	spin_lock_irqsave(&info->hit_lock, flags);
	item_count = cvector_length(info->hit_item_arr);
	spin_unlock_irqrestore(&info->hit_lock, flags);

	for (i = 0; i < item_count && copy_pos + sizeof(hit_item) <= end_pos; i++) {
		spin_lock_irqsave(&info->hit_lock, flags);
		if (i >= cvector_length(info->hit_item_arr)) {
			spin_unlock_irqrestore(&info->hit_lock, flags);
			break;
		}
		cvector_val_at(info->hit_item_arr, i, &hit_item);
		spin_unlock_irqrestore(&info->hit_lock, flags);

		if (x_copy_to_user((void __user *)copy_pos, &hit_item, sizeof(hit_item))) {
			break;
		}
		copy_pos += sizeof(hit_item);
		count++;
	}
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return count;
}

static ssize_t OnCmdSetHookPc(struct ioctl_request *hdr, char __user *buf)
{
	uint64_t pc = hdr->param1;

	printk_debug(KERN_INFO "CMD_SET_HOOK_PC pc:%px\n", (void *)pc);
	atomic64_set(&g_hook_pc, pc);
	return 0;
}

static ssize_t OnCmdHideKernelModule(struct ioctl_request *hdr, char __user *buf)
{
	printk_debug(KERN_INFO "CMD_HIDE_KERNEL_MODULE\n");
	if (g_hwBreakpointProc_devp && !g_hwBreakpointProc_devp->is_hidden_module) {
		g_hwBreakpointProc_devp->is_hidden_module = true;
		list_del_init(&__this_module.list);
		kobject_del(&THIS_MODULE->mkobj.kobj);
	}
	return 0;
}

static inline ssize_t DispatchCommand(struct ioctl_request *hdr, char __user *buf)
{
	switch (hdr->cmd) {
	case CMD_OPEN_PROCESS:
		return OnCmdOpenProcess(hdr, buf);
	case CMD_CLOSE_PROCESS:
		return OnCmdCloseProcess(hdr, buf);
	case CMD_GET_NUM_BRPS:
		return OnCmdGetCpuNumBrps(hdr, buf);
	case CMD_GET_NUM_WRPS:
		return OnCmdGetCpuNumWrps(hdr, buf);
	case CMD_INST_PROCESS_HWBP:
		return OnCmdInstProcessHwbp(hdr, buf);
	case CMD_UNINST_PROCESS_HWBP:
		return OnCmdUninstProcessHwbp(hdr, buf);
	case CMD_SUSPEND_PROCESS_HWBP:
		return OnCmdSuspendProcessHwbp(hdr, buf);
	case CMD_RESUME_PROCESS_HWBP:
		return OnCmdResumeProcessHwbp(hdr, buf);
	case CMD_GET_HWBP_HIT_COUNT:
		return OnCmdGetHwbpHitCount(hdr, buf);
	case CMD_GET_HWBP_HIT_DETAIL:
		return OnCmdGetHwbpHitDetail(hdr, buf);
	case CMD_SET_HOOK_PC:
		return OnCmdSetHookPc(hdr, buf);
	case CMD_HIDE_KERNEL_MODULE:
		return OnCmdHideKernelModule(hdr, buf);
	default:
		return -EINVAL;
	}
}

static ssize_t hwBreakpointProc_read(struct file *filp, char __user *buf,
	size_t size, loff_t *ppos)
{
	struct ioctl_request hdr = {0};
	size_t header_size = sizeof(hdr);

	if (size < header_size) {
		return -EINVAL;
	}
	if (x_copy_from_user(&hdr, buf, header_size)) {
		return -EFAULT;
	}
	if (size < header_size + hdr.buf_size) {
		return -EINVAL;
	}

	return DispatchCommand(&hdr, buf + header_size);
}

static void clean_hwbp(void)
{
	citerator iter;

	mutex_lock(&g_hwbp_handle_info_mutex);
	if (!g_hwbp_handle_info_arr) {
		mutex_unlock(&g_hwbp_handle_info_mutex);
		return;
	}

	for (iter = cvector_begin(g_hwbp_handle_info_arr);
	     iter != cvector_end(g_hwbp_handle_info_arr);
	     iter = cvector_next(g_hwbp_handle_info_arr, iter)) {
		struct HWBP_HANDLE_INFO *info = *(struct HWBP_HANDLE_INFO **)iter;

		hwbp_free_handle(info);
	}
	cvector_destroy(g_hwbp_handle_info_arr);
	g_hwbp_handle_info_arr = NULL;
	mutex_unlock(&g_hwbp_handle_info_mutex);
}

static int hwBreakpointProc_release(struct inode *inode, struct file *filp)
{
	clean_hwbp();
	mutex_lock(&g_hwbp_handle_info_mutex);
	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO *));
	mutex_unlock(&g_hwbp_handle_info_mutex);
	return g_hwbp_handle_info_arr ? 0 : -ENOMEM;
}

static int hwBreakpointProc_dev_init(void)
{
	int ret;

#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
	if (!init_kallsyms_lookup()) {
		printk(KERN_EMERG "init_kallsyms_lookup failed\n");
		return -EBADF;
	}
#endif

	mutex_init(&g_hwbp_handle_info_mutex);
	g_hwbp_handle_info_arr = cvector_create(sizeof(struct HWBP_HANDLE_INFO *));
	if (!g_hwbp_handle_info_arr) {
		ret = -ENOMEM;
		goto out_destroy_mutex;
	}

	ret = hwbp_install_inline_hooks();
	if (ret) {
		printk(KERN_EMERG "hwbp_install_inline_hooks failed:%d\n", ret);
		goto out_clean_handles;
	}

	ret = hwbp_pmu_el0_guard_start();
	if (ret) {
		printk(KERN_EMERG "hwbp_pmu_el0_guard_start failed:%d\n", ret);
		goto out_uninstall_hooks;
	}

	g_hwBreakpointProc_devp = x_kmalloc(sizeof(struct hwBreakpointProcDev), GFP_KERNEL);
	if (!g_hwBreakpointProc_devp) {
		ret = -ENOMEM;
		goto out_stop_pmu;
	}
	memset(g_hwBreakpointProc_devp, 0, sizeof(struct hwBreakpointProcDev));

#ifdef CONFIG_USE_PROC_FILE_NODE
	g_hwBreakpointProc_devp->proc_parent = proc_mkdir(CONFIG_PROC_NODE_AUTH_KEY, NULL);
	if (!g_hwBreakpointProc_devp->proc_parent) {
		ret = -ENOMEM;
		goto out_free_dev;
	}
	g_hwBreakpointProc_devp->proc_entry = proc_create(CONFIG_PROC_NODE_AUTH_KEY,
		S_IRUGO | S_IWUGO, g_hwBreakpointProc_devp->proc_parent,
		&hwBreakpointProc_proc_ops);
	if (!g_hwBreakpointProc_devp->proc_entry) {
		ret = -ENOMEM;
		goto out_remove_proc_parent;
	}
	start_hide_procfs_dir(CONFIG_PROC_NODE_AUTH_KEY);
#endif

#ifdef DEBUG_PRINTK
	printk(KERN_EMERG "Hello, %s debug\n", CONFIG_PROC_NODE_AUTH_KEY);
#else
	printk(KERN_EMERG "Hello\n");
#endif
	return 0;

#ifdef CONFIG_USE_PROC_FILE_NODE
out_remove_proc_parent:
	proc_remove(g_hwBreakpointProc_devp->proc_parent);
	g_hwBreakpointProc_devp->proc_parent = NULL;
out_free_dev:
#endif
	kfree(g_hwBreakpointProc_devp);
	g_hwBreakpointProc_devp = NULL;
out_stop_pmu:
	hwbp_pmu_el0_guard_stop();
out_uninstall_hooks:
	hwbp_uninstall_inline_hooks();
out_clean_handles:
	clean_hwbp();
out_destroy_mutex:
	mutex_destroy(&g_hwbp_handle_info_mutex);
	return ret;
}

static void hwBreakpointProc_dev_exit(void)
{
#ifdef CONFIG_USE_PROC_FILE_NODE
	if (g_hwBreakpointProc_devp && g_hwBreakpointProc_devp->proc_entry) {
		proc_remove(g_hwBreakpointProc_devp->proc_entry);
		g_hwBreakpointProc_devp->proc_entry = NULL;
	}
	if (g_hwBreakpointProc_devp && g_hwBreakpointProc_devp->proc_parent) {
		proc_remove(g_hwBreakpointProc_devp->proc_parent);
		g_hwBreakpointProc_devp->proc_parent = NULL;
	}
	stop_hide_procfs_dir();
#endif

	clean_hwbp();
	hwbp_guard_cleanup_all();
	hwbp_uninstall_inline_hooks();
	hwbp_pmu_el0_guard_stop();
	mutex_destroy(&g_hwbp_handle_info_mutex);
	kfree(g_hwBreakpointProc_devp);
	g_hwBreakpointProc_devp = NULL;
	printk(KERN_EMERG "Goodbye\n");
}

int __init init_module(void)
{
	return hwBreakpointProc_dev_init();
}

void __exit cleanup_module(void)
{
	hwBreakpointProc_dev_exit();
}

#ifndef CONFIG_MODULE_GUIDE_ENTRY
unsigned char *__check_(unsigned char *result, void *ptr, void *diag)
{
	printk_debug(KERN_EMERG "my__cfi_check_fn!!!\n");
	return result;
}

unsigned char *__check_fail_(unsigned char *result)
{
	printk_debug(KERN_EMERG "my__cfi_check_fail!!!\n");
	return result;
}
#endif

unsigned long __stack_chk_guard;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux");
MODULE_DESCRIPTION("Linux default module");
