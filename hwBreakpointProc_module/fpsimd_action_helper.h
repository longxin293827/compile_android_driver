#ifndef _FPSIMD_ACTION_HELPER_H_
#define _FPSIMD_ACTION_HELPER_H_

#include <linux/sched.h>
#include <linux/string.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include "api_proxy.h"

#define HWBP_PSTATE_NZCV_SHIFT 28
#define HWBP_PSTATE_NZCV_MASK (0xfUL << HWBP_PSTATE_NZCV_SHIFT)

static bool hwbp_write_current_s_reg(unsigned int index, uint32_t value)
{
	struct user_fpsimd_state state;
	uint32_t *lane;

	if (index >= 32) {
		return false;
	}

	if (!fpsimd_preserve_current_state_sym || !fpsimd_update_current_state_sym) {
		return false;
	}

	fpsimd_preserve_current_state_sym();
	memcpy(&state, &current->thread.uw.fpsimd_state, sizeof(state));
	lane = (uint32_t *)&state.vregs[index];
	lane[0] = value;
	fpsimd_update_current_state_sym(&state);
	return true;
}

static void hwbp_write_pstate_nzcv(struct pt_regs *regs, uint32_t nzcv)
{
	if (!regs) {
		return;
	}
	regs->pstate &= ~HWBP_PSTATE_NZCV_MASK;
	regs->pstate |= ((unsigned long)(nzcv & 0xfU) << HWBP_PSTATE_NZCV_SHIFT);
}

#endif /* _FPSIMD_ACTION_HELPER_H_ */
