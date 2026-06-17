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
#include <linux/kthread.h> // कर्नल थ्रेड के लिए
#include <linux/delay.h>   // msleep (लाइव डिले) के लिए

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel_Live_Thread_Dumper");

#define GWORLD_OFFSET 0xe4f28c0
#define PERSISTENT_LEVEL_OFFSET 0x30
#define ACTOR_ARRAY_OFFSET      0x98
#define ACTOR_COUNT_OFFSET      0xa0

// कर्नल थ्रेड ऑब्जेक्ट pointer
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

// यह फंक्शन बैकग्राउंड में लगातार लाइव चलेगा (Infinite Loop)
static int live_scan_worker(void *data) {
    printk(KERN_INFO "[LiveThread] Background worker started successfully.\n");

    // जब तक हम मॉड्यूल को rmmod नहीं करते, यह लूप चलता रहेगा
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

        // अगर गेम नहीं चल रहा, तो कर्नल शांत रहेगा और 2 सेकंड बाद फिर ढूंढेगा
        if (found_pid == 0 || base_addr == 0 || !target_mm) {
            printk(KERN_INFO "[LiveThread] Waiting for BGMI to start/match loading...\n");
            msleep(2000); 
            continue;
        }

        // अगर गेम मिल गया तो डेटा रीड करना शुरू करेंगे
        if (absolute_kernel_read(target_mm, base_addr + GWORLD_OFFSET, &gworld_ptr, sizeof(gworld_ptr)) == 0 && gworld_ptr != 0) {
            if (absolute_kernel_read(target_mm, gworld_ptr + PERSISTENT_LEVEL_OFFSET, &persistent_level, sizeof(persistent_level)) == 0 && persistent_level != 0) {
                if (absolute_kernel_read(target_mm, persistent_level + ACTOR_COUNT_OFFSET, &actor_count, sizeof(actor_count)) == 0 && actor_count > 0) {
                    absolute_kernel_read(target_mm, persistent_level + ACTOR_ARRAY_OFFSET, &actor_array, sizeof(actor_array));
                    
                    printk(KERN_INFO "[LiveThread] Live Scan -> Game PID: %d | Total Objects: %d\n", found_pid, actor_count);

                    // सिर्फ पहले 10 लाइव प्लेयर्स का रॉ डेटा लगातार प्रिंट करने के लिए
                    if (actor_count > 10) actor_count = 10;

                    for (i = 0; i < actor_count; i++) {
                        unsigned long current_actor = 0;
                        unsigned long actor_ptr_addr = actor_array + (i * 8);

                        if (absolute_kernel_read(target_mm, actor_ptr_addr, &current_actor, sizeof(current_actor)) == 0 && current_actor != 0) {
                            unsigned int chunk_1 = 0;
                            absolute_kernel_read(target_mm, current_actor + 0x0, &chunk_1, sizeof(chunk_1));
                            
                            printk(KERN_INFO "[LiveThread] [LIVE] Actor [%d] At: 0x%lx | Hex: 0x%x\n", i, current_actor, chunk_1);
                        }
                    }
                }
            }
        }

        mmput(target_mm);
        
        // गेम की स्पीड के अनुसार कर्नल थ्रेड को हर 1 सेकंड (1000ms) में री-स्कैन करने का निर्देश
        msleep(1000); 
    }

    return 0;
}

static int __init verify_init(void) {
    printk(KERN_INFO "[LiveThread] Loading Master Live Tracker Module...\n");

    // कर्नल थ्रेड को बैकग्राउंड वर्कर के रूप में रजिस्टर करना
    live_thread = kthread_run(live_scan_worker, NULL, "bgmi_live_scanner");
    if (IS_ERR(live_thread)) {
        printk(KERN_ERR "[LiveThread] Error: Failed to create kernel thread!\n");
        return PTR_ERR(live_thread);
    }

    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[LiveThread] Stopping Master Live Tracker Module...\n");
    if (live_thread) {
        kthread_stop(live_thread); // लाइव कर्नल लूप को सुरक्षित रूप से बंद करना
    }
}

module_init(verify_init);
module_exit(verify_exit);
