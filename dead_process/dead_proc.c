#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/wait.h>

int condition = 0x1234;
wait_queue_head_t waitq;

static int __init do_hacking_init(void)
{
	init_waitqueue_head(&waitq);
	wait_event(waitq, condition == 0x123);

	return 0;
}

static void __exit do_hacking_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_hacking_init);
module_exit(do_hacking_exit);
