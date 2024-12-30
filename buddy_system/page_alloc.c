#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/spinlock.h>
#include <linux/pageblock-flags.h>
#include "page_alloc.h"

static inline void del_page_from_free_list(struct page *page, struct zone *zone, unsigned int order)
{
	if (PageReported(page))
		__ClearPageReported(page);

	list_del(&page->buddy_list);
	__ClearPageBuddy(page);
	set_page_private(page, 0);
	zone->free_area[order].nr_free--;
}

struct page *get_page_from_freelist(unsigned int order)
{
	struct page *page = NULL;
	if (order > MAX_ORDER_NR_PAGES)
		return NULL;
	// in UMA system, only node 0
	struct pglist_data *node = NODE_DATA(0);
	// DMA32 if memory size < 4G
	struct zone *zone = &node->node_zones[1];
	struct free_area *free_area = &zone->free_area[order];
	spin_lock(&zone->lock);
	page = list_first_entry_or_null(&free_area->free_list[MIGRATE_MOVABLE], struct page, buddy_list);
	if (page)
		del_page_from_free_list(page, zone, order);
	spin_unlock(&zone->lock);

	return page;
}

void put_page_to_freelist(struct page *page, unsigned int order)
{
	if (order > MAX_ORDER_NR_PAGES)
		return;
	// in UMA system, only node 0
	struct pglist_data *node = NODE_DATA(0);
	// DMA32 if memory size < 4G
	struct zone *zone = &node->node_zones[1];
	struct free_area *free_area = &zone->free_area[order];
	spin_lock(&zone->lock);
	__SetPageBuddy(page);
	set_page_private(page, order);
	list_add_tail(&page->buddy_list, &free_area->free_list[MIGRATE_MOVABLE]);
	zone->free_area[order].nr_free++;
	spin_unlock(&zone->lock);
}
