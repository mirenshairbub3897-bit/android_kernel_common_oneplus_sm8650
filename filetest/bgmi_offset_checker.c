#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("simple");
MODULE_DESCRIPTION("BGMI PID Detector Kernel Module");

static int __init bgmi_init(void)
{
    struct task_struct *task;
    int found = 0;

    printk(KERN_INFO "Checking bgmi process\n");

    for_each_process(task) {

        // match possible BGMI related process names
        if (strstr(task->comm, "bgmi") ||
            strstr(task->comm, "pubg") ||
            strstr(task->comm, "imobile") ||
            strstr(task->comm, "tencent")) {

            printk(KERN_INFO "bgmi process detected pid - %d - name - %s\n",
                   task->pid,
                   task->comm);

            found = 1;
        }
    }

    if (!found) {
        printk(KERN_INFO "FAILED: BGMI process not found - reason: not running or name mismatch\n");
    }

    return 0;
}

static void __exit bgmi_exit(void)
{
    printk(KERN_INFO "bgmi detector unloaded\n");
}

module_init(bgmi_init);
module_exit(bgmi_exit);
