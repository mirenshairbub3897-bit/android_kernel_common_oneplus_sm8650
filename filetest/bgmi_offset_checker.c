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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel_Raw_Dumper");

#define GWORLD_OFFSET 0xe4f28c0
#define PERSISTENT_LEVEL_OFFSET 0x30
#define ACTOR_ARRAY_OFFSET      0x98
#define ACTOR_COUNT_OFFSET      0xa0

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

static int __init verify_init(void) {
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

    printk(KERN_INFO "[Extractor] Starting Live Raw Hex Dump... \n");

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
        printk(KERN_ERR "[Extractor] Error: Game process not found.\n");
        return 0;
    }

    if (absolute_kernel_read(target_mm, base_addr + GWORLD_OFFSET, &gworld_ptr, sizeof(gworld_ptr)) != 0 || gworld_ptr == 0) goto end;
    if (absolute_kernel_read(target_mm, gworld_ptr + PERSISTENT_LEVEL_OFFSET, &persistent_level, sizeof(persistent_level)) != 0 || persistent_level == 0) goto end;
    if (absolute_kernel_read(target_mm, persistent_level + ACTOR_COUNT_OFFSET, &actor_count, sizeof(actor_count)) != 0 || actor_count <= 0) goto end;
    if (absolute_kernel_read(target_mm, persistent_level + ACTOR_ARRAY_OFFSET, &actor_array, sizeof(actor_array)) != 0 || actor_array == 0) goto end;

    printk(KERN_INFO "[Extractor] SUCCESS! Total Array Size = %d\n", actor_count);

    // सिर्फ पहले 15 ऑब्जेक्ट्स का कच्चा चिट्ठा (Raw Data) देखने के लिए
    if (actor_count > 15) actor_count = 15;

    for (i = 0; i < actor_count; i++) {
        unsigned long current_actor = 0;
        unsigned long actor_ptr_addr = actor_array + (i * 8);

        if (absolute_kernel_read(target_mm, actor_ptr_addr, &current_actor, sizeof(current_actor)) == 0 && current_actor != 0) {
            
            unsigned int chunk_1 = 0;
            unsigned int chunk_2 = 0;

            // एक्टर के बेस एड्रेस के बिल्कुल शुरुआती हिस्सों को रीड करना
            absolute_kernel_read(target_mm, current_actor + 0x0, &chunk_1, sizeof(chunk_1));
            absolute_kernel_read(target_mm, current_actor + 0x4, &chunk_2, sizeof(chunk_2));

            // बिना किसी फिल्टर के कर्नल लॉग में लाइव एड्रेस और उसके हेक्स टोकन्स फेंकना
            printk(KERN_INFO "[Extractor] Actor [%d] Addr: 0x%lx | Header Bytes: 0x%x 0x%x\n", 
                   i, current_actor, chunk_1, chunk_2);
        }
    }

end:
    mmput(target_mm);
    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[Extractor] Extraction Module Unloaded.\n");
}

module_init(verify_init);
module_exit(verify_exit);
