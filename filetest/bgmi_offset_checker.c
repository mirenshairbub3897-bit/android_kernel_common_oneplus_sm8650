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
MODULE_AUTHOR("Kernel_Verifier_v3");

// आपके द्वारा दिए गए लाइव ऑफसेट्स
#define GNAME_OFFSET   0xdf74800
#define GWORLD_OFFSET  0xe4f28c0
#define VMATRIX_OFFSET 0xe4c9ff0
#define GUOBJECT_OFFSET 0xe22f8d0

// मॉडर्न Android 16 (Linux 6.x+) कर्नल के लिए यूनिवर्सल सेफ रीड फंक्शन
static int safe_read_kernel(struct mm_struct *mm, unsigned long addr, void *buf, int len) {
    struct page *page = NULL;
    void *vaddr;
    int res = -1;

    // मॉडर्न कर्नल्स में get_user_pages_remote के 6 पैरामीटर्स होते हैं
    res = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL);

    if (res > 0 && page) {
        vaddr = kmap_atomic(page);
        memcpy(buf, vaddr + (addr & ~PAGE_MASK), len);
        kunmap_atomic(vaddr);
        put_page(page);
        return 0; // Success
    }
    return -1; // Error
}

static int __init verify_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found_pid = 0;
    unsigned long base_addr = 0;

    printk(KERN_INFO "[Verifier] Starting Modern Kernel-Level Verification... \n");

    // 1. गेम का PID ढूंढना
    rcu_read_lock();
    for_each_process(task) {
        if (strstr(task->comm, "pubg.imobile") || strstr(task->comm, "UE4")) {
            found_pid = task->pid;
            break; 
        }
    }
    rcu_read_unlock();

    if (found_pid == 0) {
        printk(KERN_ERR "[Verifier] Error: Game is not running!\n");
        return -ESRCH; 
    }

    // 2. mm_struct एक्सेस करना
    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "[Verifier] Error: Failed to access mm_struct.\n");
        return -EINVAL;
    }

    // 3. libUE4.so का बेस एड्रेस ढूंढना
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        if (vma->vm_file) {
            const char *filename = (const char *)vma->vm_file->f_path.dentry->d_name.name;
            if (strcmp(filename, "libUE4.so") == 0) {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    if (base_addr == 0) {
        printk(KERN_ERR "[Verifier] Error: libUE4.so base address not found!\n");
        mmput(mm);
        return -ENOENT;
    }

    printk(KERN_INFO "[Verifier] Target Base Address: 0x%lx\n", base_addr);

    // 4. लाइव मेमोरी वेरिफिकेशन (Safe Remote Reading)
    unsigned long target_ptr = 0;
    float matrix_test[4] = {0}; // सरणी (Array) के रूप में फिक्स किया गया

    // क) GWorld वेरिफिकेशन टेस्ट
    unsigned long gworld_addr = base_addr + GWORLD_OFFSET;
    if (safe_read_kernel(mm, gworld_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GWorld (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", gworld_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GWorld (0x%lx) -> INVALID/NULL POINTER: 0x%lx [MISMATCH/OUTDATED]\n", gworld_addr, target_ptr);
        }
    } else {
        printk(KERN_ERR "[Verifier] GWorld Read Error: Memory page not readable.\n");
    }

    // ख) GUObject वेरिफिकेशन टेस्ट
    unsigned long guobject_addr = base_addr + GUOBJECT_OFFSET;
    if (safe_read_kernel(mm, guobject_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GUObject (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", guobject_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GUObject (0x%lx) -> INVALID/NULL POINTER: 0x%lx [MISMATCH/OUTDATED]\n", guobject_addr, target_ptr);
        }
    }

    // ग) VMatrix वेरिफिकेशन टेस्ट 
    unsigned long vmatrix_addr = base_addr + VMATRIX_OFFSET;
    if (safe_read_kernel(mm, vmatrix_addr, &matrix_test, sizeof(matrix_test)) == 0) {
        printk(KERN_INFO "[Verifier] VMatrix (0x%lx) Live Values: %f, %f, %f, %f\n", vmatrix_addr, matrix_test[0], matrix_test[1], matrix_test[2], matrix_test[3]);
    }

    mmput(mm);
    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[Verifier] Verification Module Unloaded.\n");
}

module_init(verify_init);
module_exit(verify_exit);
