#ifndef MM_H
#define MM_H
struct page *my_alloc_pages(gfp_t gfp_mask, unsigned int order);
void my_free_pages(struct page *page, unsigned int order);
#endif