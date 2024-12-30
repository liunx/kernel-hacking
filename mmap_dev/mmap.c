#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "mm.h"
#include "mmap.h"

#define ORDER 4

static void vma_open(struct vm_area_struct *vma)
{
	unsigned long num_pages = vma_pages(vma);
	unsigned long **page_addrs = kzalloc(sizeof(struct page *) * num_pages, GFP_KERNEL);
	vma->vm_private_data = page_addrs;
}

static void vma_close(struct vm_area_struct *vma)
{
	int i;
	struct page *page = NULL;
	struct page **page_addrs = vma->vm_private_data;
	for (i = 0; i < vma_pages(vma); i++) {
		page = page_addrs[i];
		my_free_pages(page, ORDER);
		// __free_pages(page, ORDER);
	}
	kfree(page_addrs);
}

static vm_fault_t vma_fault(struct vm_fault *vmf)
{
	struct page *page = NULL;
	struct page **page_addrs = vmf->vma->vm_private_data;
	// page = my_alloc_pages(0);
	/*
	 * We can choose migrate type via `| __GFP_MOVABLE` etc.
	 */
	page = my_alloc_pages(GFP_KERNEL, ORDER);
	// page = alloc_pages(GFP_KERNEL, ORDER);
	if (!page) {
		BUG_ON(page == NULL);
		// return VM_FAULT_NOPAGE;
		return VM_FAULT_OOM;
	}
	vmf->page = page;
	get_page(vmf->page);
	page_addrs[vmf->pgoff] = page;

	return 0;
}

static struct vm_operations_struct vm_ops = {
	.open = vma_open,
	.close = vma_close,
	.fault = vma_fault,
};

int dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &vm_ops;
	vma_open(vma);
	return 0;
}