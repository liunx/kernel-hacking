#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/mmzone.h>
#include <linux/spinlock.h>
#include <linux/pageblock-flags.h>
#include <linux/page_ref.h>
#include <linux/page_owner.h>
#include <linux/page_table_check.h>
#include <linux/page-isolation.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>
#include <linux/writeback.h>
#include <linux/swap.h>
#include "mm.h"

#ifdef CONFIG_ZONE_DMA32
#define ALLOC_NOFRAGMENT	0x100 /* avoid mixing pageblock types */
#else
#define ALLOC_NOFRAGMENT	  0x0
#endif

/* The ALLOC_WMARK bits are used as an index to zone->watermark */
#define ALLOC_WMARK_MIN		WMARK_MIN
#define ALLOC_WMARK_LOW		WMARK_LOW
#define ALLOC_WMARK_HIGH	WMARK_HIGH
#define ALLOC_NO_WATERMARKS	0x04 /* don't check watermarks at all */

/* Mask to get the watermark bits */
#define ALLOC_WMARK_MASK	(ALLOC_NO_WATERMARKS-1)

/*
 * Only MMU archs have async oom victim reclaim - aka oom_reaper so we
 * cannot assume a reduced access to memory reserves is sufficient for
 * !MMU
 */
#ifdef CONFIG_MMU
#define ALLOC_OOM		0x08
#else
#define ALLOC_OOM		ALLOC_NO_WATERMARKS
#endif

#define ALLOC_NON_BLOCK		 0x10 /* Caller cannot block. Allow access
				       * to 25% of the min watermark or
				       * 62.5% if __GFP_HIGH is set.
				       */
#define ALLOC_MIN_RESERVE	 0x20 /* __GFP_HIGH set. Allow access to 50%
				       * of the min watermark.
				       */
#define ALLOC_CPUSET		 0x40 /* check for correct cpuset */
#define ALLOC_CMA		 0x80 /* allow allocations from CMA areas */
#ifdef CONFIG_ZONE_DMA32
#define ALLOC_NOFRAGMENT	0x100 /* avoid mixing pageblock types */
#else
#define ALLOC_NOFRAGMENT	  0x0
#endif
#define ALLOC_HIGHATOMIC	0x200 /* Allows access to MIGRATE_HIGHATOMIC */
#define ALLOC_KSWAPD		0x800 /* allow waking of kswapd, __GFP_KSWAPD_RECLAIM set */

/* Flags that allow allocations below the min watermark. */
#define ALLOC_RESERVES (ALLOC_NON_BLOCK|ALLOC_MIN_RESERVE|ALLOC_HIGHATOMIC|ALLOC_OOM)

/* The GFP flags allowed during early boot */
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GFP_FS))
gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

struct alloc_context {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct zoneref *preferred_zoneref;
	int migratetype;

	enum zone_type highest_zoneidx;
	bool spread_dirty_pages;
};

static int fallbacks[MIGRATE_TYPES][MIGRATE_PCPTYPES - 1] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE   },
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE   },
};

static inline void del_page_from_free_list(struct page *page, struct zone *zone, unsigned int order)
{
	if (PageReported(page))
		__ClearPageReported(page);
	list_del(&page->buddy_list);
	__ClearPageBuddy(page);
	set_page_private(page, 0);
	zone->free_area[order].nr_free--;
}

static inline void add_page_to_free_list(struct page *page, struct zone *zone,
									unsigned int order, int migratetype, bool to_tail)
{
	struct free_area *free_area = &zone->free_area[order];
	if (to_tail)
		list_add_tail(&page->buddy_list, &free_area->free_list[migratetype]);
	else
		list_add(&page->buddy_list, &free_area->free_list[migratetype]);
	free_area->nr_free++;
}

static inline bool free_area_empty(struct free_area *area, int migratetype)
{
	return list_empty(&area->free_list[migratetype]);
}

static inline long __zone_watermark_unusable_free(struct zone *z,
				unsigned int order, unsigned int alloc_flags)
{
	long unusable_free = (1 << order) - 1;

	if (likely(!(alloc_flags & ALLOC_RESERVES)))
		unusable_free += z->nr_reserved_highatomic;

	return unusable_free;
}

static bool my__zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int highest_zoneidx, unsigned int alloc_flags,
			 long free_pages)
{
	long min = mark;
	int o;

	/* free_pages may go negative - that's OK */
	free_pages -= __zone_watermark_unusable_free(z, order, alloc_flags);

	if (unlikely(alloc_flags & ALLOC_RESERVES)) {
		if (alloc_flags & ALLOC_MIN_RESERVE) {
			min -= min / 2;
			if (alloc_flags & ALLOC_NON_BLOCK)
				min -= min / 4;
		}

		if (alloc_flags & ALLOC_OOM)
			min -= min / 2;
	}

	if (free_pages <= min + z->lowmem_reserve[highest_zoneidx])
		return false;

	if (!order)
		return true;

	for (o = order; o < NR_PAGE_ORDERS; o++) {
		struct free_area *area = &z->free_area[o];
		int mt;

		if (!area->nr_free)
			continue;

		for (mt = 0; mt < MIGRATE_PCPTYPES; mt++) {
			if (!free_area_empty(area, mt))
				return true;
		}

		if ((alloc_flags & (ALLOC_HIGHATOMIC|ALLOC_OOM)) &&
		    !free_area_empty(area, MIGRATE_HIGHATOMIC)) {
			return true;
		}
	}
	return false;
}

static inline bool zone_watermark_fast(struct zone *z, unsigned int order,
				unsigned long mark, int highest_zoneidx,
				unsigned int alloc_flags, gfp_t gfp_mask)
{
	long free_pages;

	free_pages = zone_page_state(z, NR_FREE_PAGES);

	if (!order) {
		long usable_free;
		long reserved;

		usable_free = free_pages;
		reserved = __zone_watermark_unusable_free(z, 0, alloc_flags);

		/* reserved may over estimate high-atomic reserves. */
		usable_free -= min(usable_free, reserved);
		if (usable_free > mark + z->lowmem_reserve[highest_zoneidx])
			return true;
	}

	if (my__zone_watermark_ok(z, order, mark, highest_zoneidx, alloc_flags,
					free_pages))
		return true;

	if (unlikely(!order && (alloc_flags & ALLOC_MIN_RESERVE) && z->watermark_boost
		&& ((alloc_flags & ALLOC_WMARK_MASK) == WMARK_MIN))) {
		mark = z->_watermark[WMARK_MIN];
		return my__zone_watermark_ok(z, order, mark, highest_zoneidx,
					alloc_flags, free_pages);
	}

	return false;
}

static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
		int preferred_nid, nodemask_t *nodemask,
		struct alloc_context *ac, gfp_t *alloc_gfp,
		unsigned int *alloc_flags)
{
	ac->highest_zoneidx = gfp_zone(gfp_mask);
	ac->zonelist = node_zonelist(preferred_nid, gfp_mask);
	ac->nodemask = nodemask;
	ac->migratetype = gfp_migratetype(gfp_mask);

	ac->preferred_zoneref = first_zones_zonelist(ac->zonelist,
					ac->highest_zoneidx, ac->nodemask);

	return true;
}

static inline unsigned int
alloc_flags_nofragment(struct zone *zone, gfp_t gfp_mask)
{
	unsigned int alloc_flags;

	/*
	 * __GFP_KSWAPD_RECLAIM is assumed to be the same as ALLOC_KSWAPD
	 * to save a branch.
	 */
	alloc_flags = (__force int) (gfp_mask & __GFP_KSWAPD_RECLAIM);

#ifdef CONFIG_ZONE_DMA32
	if (!zone)
		return alloc_flags;

	if (zone_idx(zone) != ZONE_NORMAL)
		return alloc_flags;

	BUILD_BUG_ON(ZONE_NORMAL - ZONE_DMA32 != 1);
	if (nr_online_nodes > 1 && !populated_zone(--zone))
		return alloc_flags;

	alloc_flags |= ALLOC_NOFRAGMENT;
#endif /* CONFIG_ZONE_DMA32 */
	return alloc_flags;
}


static inline void set_buddy_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

static inline void expand(struct zone *zone, struct page *page,
	int low, int high, int migratetype)
{
	unsigned long size = 1 << high;

	while (high > low) {
		high--;
		size >>= 1;

		add_page_to_free_list(&page[size], zone, high, migratetype, false);
		set_buddy_order(&page[size], high);
	}
}

static inline struct page *get_page_from_free_list(struct free_area *area,
					    int migratetype)
{
	return list_first_entry_or_null(&area->free_list[migratetype],
					struct page, buddy_list);
}

static inline void set_pcppage_migratetype(struct page *page, int migratetype)
{
	page->index = migratetype;
}

static __always_inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < NR_PAGE_ORDERS; ++current_order) {
		area = &(zone->free_area[current_order]);
		page = get_page_from_free_list(area, migratetype);
		if (!page)
			continue;
		del_page_from_free_list(page, zone, current_order);
		expand(zone, page, order, current_order, migratetype);
		set_pcppage_migratetype(page, migratetype);
		return page;
	}

	return NULL;
}

int page_group_by_mobility_disabled __read_mostly = 1;

static bool can_steal_fallback(unsigned int order, int start_mt)
{
	if (order >= pageblock_order)
		return true;

	if (order >= pageblock_order / 2 ||
		start_mt == MIGRATE_RECLAIMABLE ||
		start_mt == MIGRATE_UNMOVABLE ||
		page_group_by_mobility_disabled)
		return true;

	return false;
}

static int find_suitable_fallback(struct free_area *area, unsigned int order,
			int migratetype, bool only_stealable, bool *can_steal)
{
	int i;
	int fallback_mt;

	if (area->nr_free == 0)
		return -1;

	*can_steal = false;
	for (i = 0; i < MIGRATE_PCPTYPES - 1 ; i++) {
		fallback_mt = fallbacks[migratetype][i];
		if (free_area_empty(area, fallback_mt))
			continue;

		if (can_steal_fallback(order, migratetype))
			*can_steal = true;

		if (!only_stealable)
			return fallback_mt;

		if (*can_steal)
			return fallback_mt;
	}

	return -1;
}

static inline unsigned int buddy_order(struct page *page)
{
	/* PageBuddy() must be checked by the caller */
	return page_private(page);
}

static inline bool is_migrate_highatomic(enum migratetype migratetype)
{
	return migratetype == MIGRATE_HIGHATOMIC;
}

static void change_pageblock_range(struct page *pageblock_page,
					int start_order, int migratetype)
{
	int nr_pageblocks = 1 << (start_order - pageblock_order);

	while (nr_pageblocks--) {
		set_pageblock_migratetype(pageblock_page, migratetype);
		pageblock_page += pageblock_nr_pages;
	}
}

static inline void move_to_free_list(struct page *page, struct zone *zone,
				     unsigned int order, int migratetype)
{
	struct free_area *area = &zone->free_area[order];

	list_move_tail(&page->buddy_list, &area->free_list[migratetype]);
}

static void steal_suitable_fallback(struct zone *zone, struct page *page,
		unsigned int alloc_flags, int start_type, bool whole_block)
{
	unsigned int current_order = buddy_order(page);
	int free_pages, movable_pages, alike_pages;
	int old_block_type;
	old_block_type = get_pageblock_migratetype(page);

	if (is_migrate_highatomic(old_block_type))
		goto single_page;
	/* Take ownership for orders >= pageblock_order */
	if (current_order >= pageblock_order) {
		change_pageblock_range(page, current_order, start_type);
		goto single_page;
	}

	/* We are not allowed to try stealing from the whole block */
	if (!whole_block)
		goto single_page;

	free_pages = move_freepages_block(zone, page, start_type,
						&movable_pages);
	/* moving whole block can fail due to zone boundary conditions */
	if (!free_pages)
		goto single_page;

	if (start_type == MIGRATE_MOVABLE) {
		alike_pages = movable_pages;
	} else {
		if (old_block_type == MIGRATE_MOVABLE)
			alike_pages = pageblock_nr_pages
						- (free_pages + movable_pages);
		else
			alike_pages = 0;
	}

	if (free_pages + alike_pages >= (1 << (pageblock_order-1)) ||
			page_group_by_mobility_disabled)
		set_pageblock_migratetype(page, start_type);

	return;

single_page:
	move_to_free_list(page, zone, current_order, start_type);
}

static __always_inline bool
__rmqueue_fallback(struct zone *zone, int order, int start_migratetype,
						unsigned int alloc_flags)
{
	struct free_area *area;
	int current_order;
	int min_order = order;
	struct page *page;
	int fallback_mt;
	bool can_steal;

	if (order < pageblock_order && alloc_flags & ALLOC_NOFRAGMENT)
		min_order = pageblock_order;

	for (current_order = MAX_PAGE_ORDER; current_order >= min_order;
				--current_order) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
				start_migratetype, false, &can_steal);
		if (fallback_mt == -1)
			continue;

		if (!can_steal && start_migratetype == MIGRATE_MOVABLE
					&& current_order > order)
			goto find_smallest;

		goto do_steal;
	}

	return false;

find_smallest:
	for (current_order = order; current_order < NR_PAGE_ORDERS; current_order++) {
		area = &(zone->free_area[current_order]);
		fallback_mt = find_suitable_fallback(area, current_order,
				start_migratetype, false, &can_steal);
		if (fallback_mt != -1)
			break;
	}

	VM_BUG_ON(current_order > MAX_PAGE_ORDER);

do_steal:
	page = get_page_from_free_list(area, fallback_mt);

	steal_suitable_fallback(zone, page, alloc_flags, start_migratetype,
								can_steal);

	return true;

}

static __always_inline struct page *
__rmqueue(struct zone *zone, unsigned int order, int migratetype,
						unsigned int alloc_flags)
{
	struct page *page;

retry:
	page = __rmqueue_smallest(zone, order, migratetype);
	if (unlikely(!page)) {
		if (!page && __rmqueue_fallback(zone, order, migratetype,
								alloc_flags))
			goto retry;
	}
	return page;
}

static __always_inline
struct page *rmqueue_buddy(struct zone *preferred_zone, struct zone *zone,
			   unsigned int order, unsigned int alloc_flags,
			   int migratetype)
{
	struct page *page;
	unsigned long flags;

	do {
		page = NULL;
		spin_lock_irqsave(&zone->lock, flags);
		if (alloc_flags & ALLOC_HIGHATOMIC)
			page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);
		if (!page) {
			page = __rmqueue(zone, order, migratetype, alloc_flags);

			if (!page && (alloc_flags & ALLOC_OOM))
				page = __rmqueue_smallest(zone, order, MIGRATE_HIGHATOMIC);

			if (!page) {
				spin_unlock_irqrestore(&zone->lock, flags);
				return NULL;
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
	} while (0);

	return page;
}

static inline
struct page *rmqueue(struct zone *preferred_zone,
			struct zone *zone, unsigned int order,
			gfp_t gfp_flags, unsigned int alloc_flags,
			int migratetype)
{
	struct page *page;

	WARN_ON_ONCE((gfp_flags & __GFP_NOFAIL) && (order > 1));
	// TODO: add rmqueue_pcplist()
	page = rmqueue_buddy(preferred_zone, zone, order, alloc_flags,
							migratetype);

// out:
	/* Separate test+clear to avoid unnecessary atomics */
	if ((alloc_flags & ALLOC_KSWAPD) &&
	    unlikely(test_bit(ZONE_BOOSTED_WATERMARK, &zone->flags))) {
		clear_bit(ZONE_BOOSTED_WATERMARK, &zone->flags);
	}

	return page;
}

static inline void set_page_refcounted(struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);
	VM_BUG_ON_PAGE(page_ref_count(page), page);
	set_page_count(page, 1);
}

inline void post_alloc_hook(struct page *page, unsigned int order,
				gfp_t gfp_flags)
{
	set_page_private(page, 0);
	set_page_refcounted(page);
}

static inline void folio_set_order(struct folio *folio, unsigned int order)
{
	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
		return;

	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
#ifdef CONFIG_64BIT
	folio->_folio_nr_pages = 1U << order;
#endif
}

static inline void prep_compound_head(struct page *page, unsigned int order)
{
	struct folio *folio = (struct folio *)page;

	folio_set_order(folio, order);
	atomic_set(&folio->_entire_mapcount, -1);
	atomic_set(&folio->_nr_pages_mapped, 0);
	atomic_set(&folio->_pincount, 0);
}

static inline void prep_compound_tail(struct page *head, int tail_idx)
{
	struct page *p = head + tail_idx;

	p->mapping = TAIL_MAPPING;
	set_compound_head(p, head);
	set_page_private(p, 0);
}

static void prep_compound_page(struct page *page, unsigned int order)
{
	int i;
	int nr_pages = 1 << order;

	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++)
		prep_compound_tail(page, i);

	prep_compound_head(page, order);
}

static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
							unsigned int alloc_flags)
{
	post_alloc_hook(page, order, gfp_flags);

	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);

	if (alloc_flags & ALLOC_NO_WATERMARKS)
		set_page_pfmemalloc(page);
	else
		clear_page_pfmemalloc(page);
}

static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags,
						const struct alloc_context *ac)
{
	struct zoneref *z;
	struct zone *zone;
	struct pglist_data *last_pgdat = NULL;
	bool last_pgdat_dirty_ok = false;
	bool no_fallback;

retry:
	no_fallback = alloc_flags & ALLOC_NOFRAGMENT;
	z = ac->preferred_zoneref;
	for_next_zone_zonelist_nodemask(zone, z, ac->highest_zoneidx,
					ac->nodemask) {
		struct page *page;
		unsigned long mark;

		if (ac->spread_dirty_pages) {
			if (last_pgdat != zone->zone_pgdat) {
				last_pgdat = zone->zone_pgdat;
				last_pgdat_dirty_ok = node_dirty_ok(zone->zone_pgdat);
			}

			if (!last_pgdat_dirty_ok)
				continue;
		}

		if (no_fallback && nr_online_nodes > 1 &&
		    zone != ac->preferred_zoneref->zone) {
			int local_nid;

			local_nid = zone_to_nid(ac->preferred_zoneref->zone);
			if (zone_to_nid(zone) != local_nid) {
				alloc_flags &= ~ALLOC_NOFRAGMENT;
				goto retry;
			}
		}

		if (test_bit(ZONE_BELOW_HIGH, &zone->flags))
			goto check_alloc_wmark;

		mark = high_wmark_pages(zone);
		if (zone_watermark_fast(zone, order, mark,
					ac->highest_zoneidx, alloc_flags,
					gfp_mask))
			goto try_this_zone;
		else
			set_bit(ZONE_BELOW_HIGH, &zone->flags);

check_alloc_wmark:
		mark = wmark_pages(zone, alloc_flags & ALLOC_WMARK_MASK);
		if (!zone_watermark_fast(zone, order, mark,
				       ac->highest_zoneidx, alloc_flags,
				       gfp_mask)) {
			/* Checked here to keep the fast path fast */
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			continue;
		}

try_this_zone:
		page = rmqueue(ac->preferred_zoneref->zone, zone, order,
				gfp_mask, alloc_flags, ac->migratetype);
		if (page) {
			prep_new_page(page, order, gfp_mask, alloc_flags);

			return page;
		}
	}

	if (no_fallback) {
		alloc_flags &= ~ALLOC_NOFRAGMENT;
		goto retry;
	}

	return NULL;
}

static inline struct page *
__alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
						struct alloc_context *ac)
{
	VM_BUG_ON_PAGE(true, page);
	return NULL;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
static struct page *my__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
								nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = WMARK_LOW;
	gfp_t alloc_gfp;
	struct alloc_context ac = {};

	if (WARN_ON_ONCE(order > MAX_PAGE_ORDER))
		return NULL;

	gfp &= gfp_allowed_mask;
	gfp = current_gfp_context(gfp);
	alloc_gfp = gfp;
	if (!prepare_alloc_pages(gfp, order, preferred_nid, nodemask, &ac,
			&alloc_gfp, &alloc_flags))
		return NULL;

	alloc_flags |= alloc_flags_nofragment(ac.preferred_zoneref->zone, gfp);

	page = get_page_from_freelist(alloc_gfp, order, alloc_flags, &ac);
	if (likely(page))
		goto out;

	alloc_gfp = gfp;
	ac.spread_dirty_pages = false;

	ac.nodemask = nodemask;

	page = __alloc_pages_slowpath(alloc_gfp, order, &ac);

out:
	return page;
}

// without NUMA support!!!
struct page *my_alloc_pages(gfp_t gfp_mask, unsigned int order)
{
	int nid = numa_node_id();

	if (nid == NUMA_NO_NODE)
		nid = numa_mem_id();

	return my__alloc_pages(gfp_mask, order, nid, NULL);
}

static inline unsigned long
__find_buddy_pfn(unsigned long page_pfn, unsigned int order)
{
	return page_pfn ^ (1 << order);
}

static inline bool page_is_buddy(struct page *page, struct page *buddy, unsigned int order)
{
	if (!PageBuddy(buddy))
		return false;

	if (page_private(buddy) != order)
		return false;

	if (page_zone_id(page) != page_zone_id(buddy))
		return false;

	VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

	return true;
}

static inline struct page *
find_buddy_page_pfn(struct page *page, unsigned long pfn,
					unsigned int order, unsigned long *buddy_pfn)
{
	unsigned long __buddy_pfn = __find_buddy_pfn(pfn, order);
	struct page *buddy;

	buddy = page + (__buddy_pfn - pfn);
	if (buddy_pfn)
		*buddy_pfn = __buddy_pfn;

	if (page_is_buddy(page, buddy, order))
		return buddy;
	return NULL;
}

static __always_inline int
get_pfnblock_migratetype(const struct page *page, unsigned long pfn)
{
	return get_pfnblock_flags_mask(page, pfn, MIGRATETYPE_MASK);
}

static inline bool
buddy_merge_likely(unsigned long pfn, unsigned long buddy_pfn,
		   struct page *page, unsigned int order)
{
	unsigned long higher_page_pfn;
	struct page *higher_page;

	if (order >= MAX_PAGE_ORDER - 1)
		return false;

	higher_page_pfn = buddy_pfn & pfn;
	higher_page = page + (higher_page_pfn - pfn);

	return find_buddy_page_pfn(higher_page, higher_page_pfn, order + 1,
			NULL) != NULL;
}

static inline bool pcp_allowed_order(unsigned int order)
{
	if (order <= PAGE_ALLOC_COSTLY_ORDER)
		return true;
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (order == pageblock_order)
		return true;
#endif
	return false;
}

static __always_inline bool free_pages_prepare(struct page *page, unsigned int order)
{
	VM_BUG_ON_PAGE(PageTail(page), page);

	if (unlikely(order)) {
		int i;

		for (i = 1; i < (1 << order); i++) {
			(page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
		}
	}
	if (PageMappingFlags(page))
		page->mapping = NULL;

	page_cpupid_reset_last(page);
	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	reset_page_owner(page, order);
	page_table_check_free(page, order);

	return true;
}

static inline void __free_one_page(struct page *page,
		unsigned long pfn,
		struct zone *zone, unsigned int order,
		int migratetype)
{
	unsigned long buddy_pfn = 0;
	unsigned long combined_pfn;
	struct page *buddy;
	bool to_tail;

	VM_BUG_ON(!zone_is_initialized(zone));
	VM_BUG_ON_PAGE(page->flags & PAGE_FLAGS_CHECK_AT_PREP, page);

	VM_BUG_ON(migratetype == -1);
	if (likely(!is_migrate_isolate(migratetype)))
		__mod_zone_freepage_state(zone, 1 << order, migratetype);

	VM_BUG_ON_PAGE(pfn & ((1 << order) - 1), page);

	while (order < MAX_PAGE_ORDER) {
		buddy = find_buddy_page_pfn(page, pfn, order, &buddy_pfn);
		if (!buddy)
			goto done_merging;

		if (unlikely(order >= pageblock_order)) {
			int buddy_mt = get_pfnblock_migratetype(buddy, buddy_pfn);

			if (migratetype != buddy_mt
					&& (!migratetype_is_mergeable(migratetype) ||
						!migratetype_is_mergeable(buddy_mt)))
				goto done_merging;
		}

		del_page_from_free_list(buddy, zone, order);
		combined_pfn = buddy_pfn & pfn;
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		order++;
	}

done_merging:
	set_buddy_order(page, order);
	to_tail = buddy_merge_likely(pfn, buddy_pfn, page, order);
	add_page_to_free_list(page, zone, order, migratetype, to_tail);
}

static void free_one_page(struct zone *zone,
				struct page *page, unsigned long pfn,
				unsigned int order,
				int migratetype)
{
	unsigned long flags;

	spin_lock_irqsave(&zone->lock, flags);
	__free_one_page(page, pfn, zone, order, migratetype);
	spin_unlock_irqrestore(&zone->lock, flags);
}

static void __free_pages_ok(struct page *page, unsigned int order)
{
	int migratetype;
	unsigned long pfn = page_to_pfn(page);
	struct zone *zone = page_zone(page);

	if (!free_pages_prepare(page, order))
		return;

	migratetype = get_pfnblock_migratetype(page, pfn);

	free_one_page(zone, page, pfn, order, migratetype);
}

static inline void free_the_page(struct page *page, unsigned int order)
{
	// TODO: add free to pcplist
	__free_pages_ok(page, order);
}

void my_free_pages(struct page *page, unsigned int order)
{
	int head = PageHead(page);

	if (put_page_testzero(page))
		free_the_page(page, order);
	else if (!head) {
		while (order-- > 0)
			free_the_page(page + (1 << order), order);
	}
}
