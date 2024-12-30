#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/wait.h>

static int __init do_hacking_init(void)
{
	wait_queue_head_t *wait = (wait_queue_head_t *)0xffffffffa02034c0;
	wake_up(wait);
	return -1;
}

static void __exit do_hacking_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_hacking_init);
module_exit(do_hacking_exit);
