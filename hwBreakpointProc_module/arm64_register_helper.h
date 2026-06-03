# ifndef __ARM64_REGISTER_HELPER_H__
# define __ARM64_REGISTER_HELPER_H__
#include <linux/module.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>

static int getCpuNumBrps(void) {
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}

static int getCpuNumWrps(void) {
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}
#endif
