#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("debug");
MODULE_DESCRIPTION("libUE4.so VMA base finder");

static pid_t target_pid = 0; // optional: set manually if needed

static void scan_process_vma(struct task_struct *task)
{
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    mm = task->mm;
    if (!mm)
        return;

    printk(KERN_INFO "[VMA] Scanning PID: %d NAME: %s\n",
           task->pid, task->comm);

    for (vma = mm->mmap; vma; vma = vma->vm_next) {

        if (vma->vm_file) {
            char buf[256];
            char *name;

            name = d_path(&vma->vm_file->f_path, buf, sizeof(buf));

            if (!IS_ERR(name)) {

                // match libUE4.so
                if (strstr(name, "libUE4.so")) {

                    printk(KERN_INFO "[FOUND] libUE4.so\n");
                    printk(KERN_INFO "[BASE] PID: %d NAME: %s\n",
                           task->pid,
                           task->comm);

                    printk(KERN_INFO "[ADDR] vm_start = 0x%lx vm_end = 0x%lx\n",
                           vma->vm_start,
                           vma->vm_end);
                }
            }
        }
    }
}

static int __init vma_init(void)
{
    struct task_struct *task;

    printk(KERN_INFO "[INIT] Starting VMA scan...\n");

    for_each_process(task) {

        // OPTIONAL FILTER (reduce noise)
        if (strstr(task->comm, "bgmi") ||
            strstr(task->comm, "pubg") ||
            strstr(task->comm, "imobile") ||
            strstr(task->comm, "ue4") ||
            target_pid == task->pid) {

            scan_process_vma(task);
        }
    }

    printk(KERN_INFO "[DONE] Scan complete\n");
    return 0;
}

static void __exit vma_exit(void)
{
    printk(KERN_INFO "[EXIT] Module removed\n");
}

module_init(vma_init);
module_exit(vma_exit);
