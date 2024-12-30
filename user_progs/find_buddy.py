#!/usr/bin/env python3

MAX_PAGE_ORDER = 11

def demo01(pfn, order):
    while (order < MAX_PAGE_ORDER):
        buddy_pfn = pfn ^ (1 << order)
        print("pfn: 0x{:x}, buddy: 0x{:x}, order: {}".format(pfn, buddy_pfn, order))
        pfn = buddy_pfn & pfn
        order += 1

if __name__ == '__main__':
    demo01(0x1a0a, 1)
