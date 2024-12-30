#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAGE_ORDER 10

struct page {
    unsigned int flags;
    unsigned int order;
};

struct page *alloc_pages(unsigned int order)
{
    if (order < 9)
        return NULL;
    struct page *pages = (struct page *)malloc(sizeof(struct page) * (1 << order));
    memset(pages, 0, sizeof(struct page) * (1 << order));
    pages->order = order;
    return pages;
}

int demo(unsigned int order)
{
    int i;
    struct page *pg;
    unsigned int max_order = 0;
    struct page *pages[MAX_PAGE_ORDER];
    for (i = order; i <= MAX_PAGE_ORDER; i++) {
        pg = alloc_pages(i);
        if (pg)
            break;
    }

    if (order == i) {
        printf("pg: %p, page->order: %d\n", pg, pg->order);
        return 0;
    }
    max_order = i;
    printf("max_order: %d\n", max_order);
    while (--i > order) {
        pages[i] = pg + (1 << i);
        pages[i]->order = i;
        printf("pg: %p, i = %d\n", pages[i], i);
    }

    pg->order = order;
    printf("pg: %p, page->order: %d\n", pg, pg->order);

    for (i = order + 1; i < max_order; i++) {
        pg = pages[i];
        printf("pages[%d]->order: %d\n", i, pg->order);
    }
}

static void free_pages(struct page *page, unsigned int order)
{
    struct page *buddy;
    while (order < MAX_PAGE_ORDER) {
        buddy = page + (1 << order);
    }

}

int main(const int argc, char *argv[])
{
    struct page *pages = (struct page *)malloc(sizeof(struct page) * (1 << (MAX_PAGE_ORDER + 1)));
    if (argc != 2) {
        printf("help: %s order\n", argv[0]);
        return -1;
    }
    printf("sizeof struct page: %ld\n", sizeof(struct page));
    unsigned int order = atoi(argv[1]);

    free(pages);

    return 0;
}