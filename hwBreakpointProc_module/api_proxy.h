#ifndef _API_PROXY_H_
#define _API_PROXY_H_

#include "ver_control.h"
#include <linux/slab.h>
#include <linux/uaccess.h>

#ifdef CONFIG_KALLSYMS_LOOKUP_NAME
#include "kallsyms_lookup_api.h"
#endif

static void *x_kmalloc(size_t size, gfp_t flags)
{
	return __kmalloc(size, flags);
}

static unsigned long x_copy_from_user(void *to, const void __user *from,
	unsigned long n)
{
	return __arch_copy_from_user(to, from, n);
}

static unsigned long x_copy_to_user(void __user *to, const void *from,
	unsigned long n)
{
	return __arch_copy_to_user(to, from, n);
}

#endif
