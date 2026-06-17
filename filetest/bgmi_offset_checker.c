#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel_Live_Debugger");

#define GWORLD_OFFSET 0xe4f28c0
#define PERSISTENT_LEVEL_OFFSET 0x30
#define ACTOR_ARRAY_OFFSET      0x98
#define ACTOR_COUNT_OFFSET      0xa0

static struct task_struct *live_thread = NULL;

static int absolute_kernel_read(struct mm_struct *mm, unsigned long addr, void *buf, int len) {
    struct page *page = NULL;
    void *vaddr;
    long res;

    res = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);
    if (res > 0 && page) {
        vaddr = kmap_local_page(page);
        memcpy(buf, vaddr + (addr & ~PAGE_MASK), len);
        kunmap_local(vaddr);
        put_page(page);
        return 0; 
    }
    return -1; 
}

static int live_scan_worker(void *data) {
    printk(KERN_INFO "[LiveThread] Background worker loop started.\n");

    while (!kthread_should_stop()) {
        struct task_struct *task;
        struct vm_area_struct *vma;
        struct mm_struct *target_mm = NULL;
        int found_pid = 0;
        unsigned long base_addr = 0;

        unsigned long gworld_ptr = 0;
        unsigned long persistent_level = 0;
        unsigned long actor_array = 0;
        int actor_count = 0;
        int i = 0;

        rcu_read_lock();
        for_each_process(task) {
            struct mm_struct *active_mm = get_task_mm(task);
            if (active_mm) {
                VMA_ITERATOR(vmi, active_mm, 0);
                for_each_vma(vmi, vma) {
                    if (vma->vm_file) {
                        const char *filename = (const char *)vma->vm_file->f_path.dentry->d_name.name;
                        if (strcmp(filename, "libUE4.so") == 0) {
                            found_pid = task->pid;
                            base_addr = vma->vm_start;
                            target_mm = active_mm;
                            break;
                        }
                    }
                }
                if (found_pid == 0) {
                    mmput(active_mm);
                }
            }
            if (found_pid != 0) break;
        }
        rcu_read_unlock();

        if (found_pid == 0 || base_addr == 0 || !target_mm) {
            printk(KERN_INFO "[LiveThread] [DEBUG] Game process NOT found in process tree.\n");
            msleep(2000); 
            continue;
        }

        printk(KERN_INFO "[LiveThread] [DEBUG] Game Found! PID: %d | Base: 0x%lx. Testing GWorld...\n", found_pid, base_addr);

        // स्टेप-बाय-स्टेप लाइव कर्नल डिबगिंग
        if (absolute_kernel_read(target_mm, base_addr + GWORLD_OFFSET, &gworld_ptr, sizeof(gworld_ptr)) != 0 || gworld_ptr == 0) {
            printk(KERN_WARNING "[LiveThread] [DEBUG] GWorld Read FAILED at 0x%lx\n", base_addr + GWORLD_OFFSET);
            goto loop_end;
        }
        
        printk(KERN_INFO "[LiveThread] [DEBUG] GWorld Pointer Success: 0x%lx. Testing PersistentLevel...\n", gworld_ptr);

        if (absolute_kernel_read(target_mm, gworld_ptr + PERSISTENT_LEVEL_OFFSET, &persistent_level, sizeof(persistent_level)) != 0 || persistent_level == 0) {
            printk(KERN_WARNING "[LiveThread] [DEBUG] PersistentLevel Read FAILED at 0x%lx\n", gworld_ptr + PERSISTENT_LEVEL_OFFSET);
            goto loop_end;
        }

        if (absolute_kernel_read(target_mm, persistent_level + ACTOR_COUNT_OFFSET, &actor_count, sizeof(actor_count)) != 0 || actor_count <= 0) {
            printk(KERN_WARNING "[LiveThread] [DEBUG] ActorCount Read FAILED or Zero.\n");
            goto loop_end;
        }

        absolute_kernel_read(target_mm, persistent_level + ACTOR_ARRAY_OFFSET, &actor_array, sizeof(actor_array));
        
        printk(KERN_INFO "[LiveThread] [LIVE] PID: %d | Total Objects: %d\n", found_pid, actor_count);

        if (actor_count > 5) actor_count = 5; // सिर्फ शुरुआती 5 टेस्ट करने के लिए

        for (i = 0; i < actor_count; i++) {
            unsigned long current_actor = 0;
            unsigned long actor_ptr_addr = actor_array + (i * 8);

            if (absolute_kernel_read(target_mm, actor_ptr_addr, &current_actor, sizeof(current_actor)) == 0 && current_actor != 0) {
                unsigned int chunk = 0;
                absolute_kernel_read(target_mm, current_actor + 0x0, &chunk, sizeof(chunk));
                printk(KERN_INFO "[LiveThread] -> Actor [%d]: 0x%lx | ID: 0x%x\n", i, current_actor, chunk);
            }
        }

loop_end:
        mmput(target_mm);
        msleep(1500); // 1.5 सेकंड का लाइव डिले
    }
    return 0;
}

static int __init verify_init(void) {
    printk(KERN_INFO "[LiveThread] Loading Master Live Tracker Module...\n");
    live_thread = kthread_run(live_scan_worker, NULL, "bgmi_live_scanner");
    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[LiveThread] Stopping Master Live Tracker Module...\n");
    if (live_thread) kthread_stop(live_thread);
}

module_init(verify_init);
module_exit(verify_exit);
