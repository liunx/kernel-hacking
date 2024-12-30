#ifndef MMAP_H
#define MMAP_H
int dev_mmap(struct file *filp, struct vm_area_struct *vma);
#endif