#ifndef _PMU_EL0_GUARD_H_
#define _PMU_EL0_GUARD_H_

#include <linux/cpuhotplug.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <asm/sysreg.h>

#ifndef ID_AA64DFR0_EL1_PMUVer_SHIFT
#define ID_AA64DFR0_EL1_PMUVer_SHIFT 8
#endif

static DEFINE_PER_CPU(u64, hwbp_saved_pmuserenr_el0);
static DEFINE_PER_CPU(bool, hwbp_saved_pmuserenr_valid);
static int hwbp_pmu_cpuhp_state = CPUHP_INVALID;

static bool hwbp_cpu_has_pmuv3(void)
{
	u64 pmuver = (read_cpuid(ID_AA64DFR0_EL1) >> ID_AA64DFR0_EL1_PMUVer_SHIFT) & 0xf;

	return pmuver >= 1 && pmuver != 0xf;
}

static void hwbp_disable_pmuserenr_on_cpu(void)
{
	if (!hwbp_cpu_has_pmuv3()) {
		return;
	}

	if (!this_cpu_read(hwbp_saved_pmuserenr_valid)) {
		this_cpu_write(hwbp_saved_pmuserenr_el0, read_sysreg(pmuserenr_el0));
		this_cpu_write(hwbp_saved_pmuserenr_valid, true);
	}
	write_sysreg(0, pmuserenr_el0);
	isb();
}

static void hwbp_restore_pmuserenr_on_cpu(void)
{
	if (!hwbp_cpu_has_pmuv3() || !this_cpu_read(hwbp_saved_pmuserenr_valid)) {
		return;
	}

	write_sysreg(this_cpu_read(hwbp_saved_pmuserenr_el0), pmuserenr_el0);
	isb();
	this_cpu_write(hwbp_saved_pmuserenr_valid, false);
}

static void hwbp_disable_pmuserenr_call(void *unused)
{
	hwbp_disable_pmuserenr_on_cpu();
}

static void hwbp_restore_pmuserenr_call(void *unused)
{
	hwbp_restore_pmuserenr_on_cpu();
}

static int hwbp_pmu_cpu_online(unsigned int cpu)
{
	hwbp_disable_pmuserenr_on_cpu();
	return 0;
}

static int hwbp_pmu_cpu_offline(unsigned int cpu)
{
	hwbp_restore_pmuserenr_on_cpu();
	return 0;
}

static int hwbp_pmu_el0_guard_start(void)
{
	int state;

	on_each_cpu(hwbp_disable_pmuserenr_call, NULL, 1);

	state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
		"hwbp_proc/pmu_el0_guard:online",
		hwbp_pmu_cpu_online, hwbp_pmu_cpu_offline);
	if (state < 0) {
		on_each_cpu(hwbp_restore_pmuserenr_call, NULL, 1);
		return state;
	}

	hwbp_pmu_cpuhp_state = state;
	return 0;
}

static void hwbp_pmu_el0_guard_stop(void)
{
	if (hwbp_pmu_cpuhp_state != CPUHP_INVALID) {
		cpuhp_remove_state(hwbp_pmu_cpuhp_state);
		hwbp_pmu_cpuhp_state = CPUHP_INVALID;
	}
	on_each_cpu(hwbp_restore_pmuserenr_call, NULL, 1);
}

#endif
