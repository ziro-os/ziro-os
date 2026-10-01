// SPDX-License-Identifier: GPL-2.0
// Minimal out-of-tree module for the Ziro kernel: ziroctl dev kmod build sdk/examples/kmod-hello
#include <linux/init.h>
#include <linux/module.h>

static int __init hello_init(void)
{
	pr_info("ziro-hello: loaded\n");
	return 0;
}

static void __exit hello_exit(void)
{
	pr_info("ziro-hello: unloaded\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ziro OS SDK example module");
