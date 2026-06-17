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
MODULE_AUTHOR("Kernel_SDK_Extractor");

// आपके द्वारा खोजे गए मुख्य ऑफसेट्स
#define GWORLD_OFFSET 0xe4f28c0

// Unreal Engine 4 SDK ऑफसेट्स जो आपने शेयर किए
#define PERSISTENT_LEVEL_OFFSET 0x30  // GWorld -> PersistentLevel
#define ACTOR_ARRAY_OFFSET      0x98  // PersistentLevel -> ActorArray
#define ACTOR_COUNT_OFFSET      0xa0  // PersistentLevel -> ActorCount

// खिलाड़ियों के अंदरूनी ऑफसेट्स (आपके शेयर किए गए लॉग्स के अनुसार)
#define HEALTH_OFFSET           0xe60  // Actor -> Health (Float वैल्यू)
#define IS_AI_OFFSET            0xa59  // Actor -> bIsAI (1 बाइट का बूलियन)
#define TEAM_ID_OFFSET          0x998  // Actor -> TeamID (इंटीजर वैल्यू)

// यूनिवर्सल पेज रीडर फंक्शन जो Android 16 में ब्लॉक नहीं होता
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

    printk(KERN_INFO "[Extractor] Starting Live SDK Extraction... \n");

    // 1. गेम का PID और libUE4.so बेस एड्रेस ढूंढना
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
        printk(KERN_ERR "[Extractor] Error: Game process not found in RAM.\n");
        return 0;
    }

    // 2. GWorld -> PersistentLevel -> ActorArray की चेन को पढ़ना
    if (absolute_kernel_read(target_mm, base_addr + GWORLD_OFFSET, &gworld_ptr, sizeof(gworld_ptr)) != 0 || gworld_ptr == 0) goto end;
    if (absolute_kernel_read(target_mm, gworld_ptr + PERSISTENT_LEVEL_OFFSET, &persistent_level, sizeof(persistent_level)) != 0 || persistent_level == 0) goto end;
    if (absolute_kernel_read(target_mm, persistent_level + ACTOR_COUNT_OFFSET, &actor_count, sizeof(actor_count)) != 0 || actor_count <= 0) goto end;
    if (absolute_kernel_read(target_mm, persistent_level + ACTOR_ARRAY_OFFSET, &actor_array, sizeof(actor_array)) != 0 || actor_array == 0) goto end;

    printk(KERN_INFO "[Extractor] Game Running! Total Objects in Array = %d\n", actor_count);

    // टेस्ट के लिए हम पहले 150 ऑब्जेक्ट्स को लाइव स्कैन करेंगे
    if (actor_count > 150) actor_count = 150;

    // 3. कर्नल लूप: एक-एक खिलाड़ी के अंदर जाकर SDK ऑफसेट्स को रीड करना
    for (i = 0; i < actor_count; i++) {
        unsigned long current_actor = 0;
        unsigned long actor_ptr_addr = actor_array + (i * 8);

        if (absolute_kernel_read(target_mm, actor_ptr_addr, &current_actor, sizeof(current_actor)) == 0 && current_actor != 0) {
            
            // कर्नल वैरिएबल्स लाइव डेटा होल्ड करने के लिए (No float math, just raw bits representation)
            unsigned int raw_health = 0;
            unsigned char is_ai = 0;
            int team_id = 0;

            // अ) लाइव हेल्थ रीड करें (Offset 0xe60)
            absolute_kernel_read(target_mm, current_actor + HEALTH_OFFSET, &raw_health, sizeof(raw_health));

            // ब) बोट/एआई स्टेटस रीड करें (Offset 0xa59)
            absolute_kernel_read(target_mm, current_actor + IS_AI_OFFSET, &is_ai, sizeof(is_ai));

            // स) टीम आईडी नंबर रीड करें (Offset 0x998)
            absolute_kernel_read(target_mm, current_actor + TEAM_ID_OFFSET, &team_id, sizeof(team_id));

            // सिर्फ उन्हीं ऑब्जेक्ट्स को प्रिंट करें जिनकी हेल्थ वैलिड है (फालतू दीवारों और गन्स को फ़िल्टर करने के लिए)
            if (raw_health != 0 && team_id > 0 && team_id < 100) {
                printk(KERN_INFO "[Extractor] Player [%d] Found -> TeamID: %d | Is_Bot: %s\n", 
                       i, team_id, (is_ai == 1) ? "YES" : "NO");
            }
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
