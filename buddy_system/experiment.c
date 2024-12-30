#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/spinlock.h>
#include <linux/pageblock-flags.h>

static void experiment(void)
{
	int i;
	struct zone *zone;
	struct free_area *free_area;
	struct list_head *free_list;
	struct pglist_data *node = NODE_DATA(0);
	pr_info("node->nr_zones: %d\n", node->nr_zones);
	for (i = 0; i < node->nr_zones; i++) {
		zone = &node->node_zones[i];
		pr_info("node %s:\n", zone->name);
		pr_info("high_wmark_pages: %ld\n", high_wmark_pages(zone));
		pr_info("low_wmark_pages: %ld\n", low_wmark_pages(zone));
		pr_info("min_wmark_pages: %ld\n", min_wmark_pages(zone));
		free_area = zone->free_area;
		pr_info("free_area->nr_free: %ld\n", free_area->nr_free);
		free_list = free_area[0].free_list;
	}
}

static struct page *do_alloc_pages(unsigned int order)
{
	unsigned long nr_free = 0;
	struct list_head *pos;
	struct page *page;
	int count = 0;
	int i;
	if (order > MAX_ORDER_NR_PAGES)
		return NULL;
	// in UMA system, only node 0
	struct pglist_data *node = NODE_DATA(0);
	// DMA32 if memory size < 4G
	struct zone *zone = &node->node_zones[1];
	struct free_area *free_area = &zone->free_area[order];
	spin_lock(&zone->lock);
	nr_free = free_area->nr_free;
	list_for_each(pos, &free_area->free_list[MIGRATE_MOVABLE]) {
		page = list_entry(pos, struct page, buddy_list);
		pr_info("page: 0x%lx{\n", (unsigned long)page);
		// 检测 buddy system 是否做复合页处理
		if (test_bit(PG_head, &page->flags))
			pr_info("It's a PG_head!\n");
		if (test_bit(PG_lru, &page->flags))
			pr_info("It's a PG_lru!\n");
		for (i = 0; i < (1 << order); i++) {
			struct page *p = page + i;
			pr_info("page: 0x%lx\n", (unsigned long)p);
			pr_info("mapcount: %d\n", atomic_read(&p->_mapcount));
			pr_info("refcount: %d\n", atomic_read(&p->_refcount));
			pr_info("private: %ld\n", p->private);
			pr_info("index: %ld\n", p->index);
			count++;
		}
		pr_info("total pages: %d\n", count);
		count = 0;
		pr_info("}\n");
	}

	spin_unlock(&zone->lock);
	pr_info("nr_free: %ld\n", free_area->nr_free);

	return NULL;
}

static int __init do_module_init(void)
{
	// experiment();
	do_alloc_pages(2);
	return 0;
}

static void __exit do_module_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_module_init);
module_exit(do_module_exit);
