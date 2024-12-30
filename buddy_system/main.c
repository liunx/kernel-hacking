#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include "page_alloc.h"

/*
 * 我们取代了伙伴系统来分配页面，如果不释放回去，那么内存泄漏在所难免，并且我们没有
 * 通过伙伴系统来分配，内存泄漏等调试功能也无法感知到，结论是自己挖的坑自己填吧。
 */
static void demo_leak_pages(void)
{
	struct page *page = NULL;
	do {
		page = get_page_from_freelist(10);
		if (page == NULL)
			break;
		put_page_to_freelist(page, 10);
	} while (0);
}

static void demo_alloc_pages(void)
{
	struct page *page = get_page_from_freelist(2);
	// echo 1 > /proc/sys/kernel/kptr_restrict
	pr_info("page: 0x%pK\n", page);
}

static int __init do_module_init(void)
{
	demo_leak_pages();
	return 0;
}

static void __exit do_module_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_module_init);
module_exit(do_module_exit);