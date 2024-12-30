#ifndef PAGE_ALLOC_H
#define PAGE_ALLOC_H
struct page *get_page_from_freelist(unsigned int order);
void put_page_to_freelist(struct page *page, unsigned int order);
#endif