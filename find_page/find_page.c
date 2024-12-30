#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>

static uint pid = 1;
module_param(pid, uint, 0644);
static unsigned long vaddr = 0x0;
module_param(vaddr, long, 0644);

static pte_t *get_pte(struct task_struct *task, unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct mm_struct *mm = task->mm;

	pgd = pgd_offset(mm, vaddr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte))
		return NULL;

	return pte;
}

static int __init do_hacking_init(void)
{
	struct task_struct *task = NULL;
	struct page *page;
	pte_t *pte;
	unsigned long paddr;
	unsigned long poffset;
	char data[] = {0xff, 0xff, 0x66, 0x66, 0x66, 0x66, 0xff, 0xff};

	task = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);
	if (!(pte = get_pte(task, vaddr)))
		return -1;
	pr_info("pte addr: 0x%p, val: 0x%lx, offset: 0x%lx\n", pte, pte_val(*pte), pte_index(vaddr));
	page = pte_page(*pte);
	paddr = (unsigned long)page_address(page);
	poffset = vaddr & ~PAGE_MASK;
	pr_info("paddr: 0x%lx\n", paddr);
	memcpy((void *)(paddr + poffset), data, sizeof(data));

	return 0;
}

static void __exit do_hacking_exit(void)
{
}

MODULE_LICENSE("GPL");

module_init(do_hacking_init);
module_exit(do_hacking_exit);
