#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include "mmap.h"

static dev_t devno;
static const int minor = 0;
struct cdev cdev;

static int dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int dev_close(struct inode *inode, struct file *filp)
{
	return 0;
}

struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_close,
	.mmap = dev_mmap,
};

static int __init do_module_init(void)
{
	int err;
	err = alloc_chrdev_region(&devno, minor, 1, KBUILD_MODNAME);
	if (err)
		return err;
	pr_alert("mknod /dev/mmap_dev c %d %d\n", MAJOR(devno), minor);
	cdev_init(&cdev, &dev_fops);
	err = cdev_add(&cdev, devno, 1);
	if (err)
		pr_info("Error %d adding cdev!", err);
	cdev.owner = THIS_MODULE;
	return 0;
}

static void __exit do_module_exit(void)
{
	if (devno)
		unregister_chrdev_region(devno, 1);
}

MODULE_LICENSE("GPL");

module_init(do_module_init);
module_exit(do_module_exit);