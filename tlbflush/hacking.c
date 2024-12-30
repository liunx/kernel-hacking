#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#define FLUSH_TLB_ALL 0xffffffff89680db0
#define PMD_ADDR 0xffff9f3f5ac0e258

void (*pf)(void);

static void modify_ptable(void)
{
	pf = (void *)FLUSH_TLB_ALL;
	unsigned long *p = (unsigned long *)PMD_ADDR;
	*p = 0x00000000592000e3;
	pf();
}

static void modify_func(void)
{
	// mov eax, 1; ret
	char codes[] = {0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};
	char *func = (char *)0xffffffff8967b9f5;
	memcpy(func, codes, sizeof(codes));
}

static int __init do_hacking_init(void)
{
	modify_ptable();
	rmb();
	modify_func();
	return -1;
}

static void __exit do_hacking_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_hacking_init);
module_exit(do_hacking_exit);
