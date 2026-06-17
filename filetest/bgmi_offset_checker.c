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
MODULE_AUTHOR("Kernel_Verifier_V6_PageMap");

#define GNAME_OFFSET   0xdf74800
#define GWORLD_OFFSET  0xe4f28c0
#define VMATRIX_OFFSET 0xe4c9ff0
#define GUOBJECT_OFFSET 0xe22f8d0

// Android 16 GKI कम्पैटिबल अल्टीमेट कर्नल पेज रीडर
static int absolute_kernel_read(struct mm_struct *mm, unsigned long addr, void *buf, int len) {
    struct page *page = NULL;
    void *vaddr;
    long res;

    // कर्नल डायरेक्ट रैम से पेज को पिन (pin) कर लेता है, एंटी-चीट इसे ब्लॉक नहीं कर सकता
    res = get_user_pages_remote(mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);

    if (res > 0 && page) {
        // मॉडर्न कर्नल (Linux 6.x+) में पेज को कर्नल स्पेस में लाइव मैप करने का सबसे सेफ तरीका
        vaddr = kmap_local_page(page);
        memcpy(buf, vaddr + (addr & ~PAGE_MASK), len);
        kunmap_local(vaddr);
        put_page(page);
        return 0; // Success
    }
    return -1; // Error
}

static int __init verify_init(void) {
    struct task_struct *task;
    struct vm_area_struct *vma;
    struct mm_struct *target_mm = NULL;
    int found_pid = 0;
    unsigned long base_addr = 0;

    printk(KERN_INFO "[Verifier] Starting Absolute Page-Map Verification... \n");

    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *active_mm = get_task_mm(task);
        if (active_mm) {
            VMA_ITERATOR(vmi, active_mm, 0);
            for_each_vma(vmi, vma) {
                if (vma->vm_file) {
                    const char *filename = (const char *)vma->vm_file->f_path.dentry->d_name.name;
                    if (strcmp(filename, "libUE4.so") == 0 || strcmp(filename, "libanogs.so") == 0) {
                        found_pid = task->pid;
                        base_addr = vma->vm_start;
                        target_mm = active_mm; // mm_struct को होल्ड कर लिया
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
        printk(KERN_ERR "[Verifier] Error: BGMI Process or libUE4.so NOT found in RAM!\n");
        return 0;
    }

    printk(KERN_INFO "[Verifier] SUCCESS! Auto-Found PID = %d\n", found_pid);
    printk(KERN_INFO "[Verifier] Target Base Address: 0x%lx\n", base_addr);

    unsigned long target_ptr = 0;
    unsigned int matrix_bytes = 0;

    // क) GWorld टेस्ट
    unsigned long gworld_addr = base_addr + GWORLD_OFFSET;
    if (absolute_kernel_read(target_mm, gworld_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GWorld (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", gworld_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GWorld (0x%lx) -> INVALID POINTER: 0x%lx [MISMATCH]\n", gworld_addr, target_ptr);
        }
    } else {
        printk(KERN_ERR "[Verifier] GWorld Page Mapping Failed.\n");
    }

    // ख) GUObject टेस्ट
    unsigned long guobject_addr = base_addr + GUOBJECT_OFFSET;
    if (absolute_kernel_read(target_mm, guobject_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GUObject (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", guobject_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GUObject (0x%lx) -> INVALID POINTER: 0x%lx [MISMATCH]\n", guobject_addr, target_ptr);
        }
    }

    // ग) VMatrix टेस्ट
    unsigned long vmatrix_addr = base_addr + VMATRIX_OFFSET;
    if (absolute_kernel_read(target_mm, vmatrix_addr, &matrix_bytes, sizeof(matrix_bytes)) == 0) {
        printk(KERN_INFO "[Verifier] VMatrix (0x%lx) Raw Value: 0x%x\n", vmatrix_addr, matrix_bytes);
    }

    mmput(target_mm);
    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[Verifier] Verification Module Unloaded.\n");
}

module_init(verify_init);
module_exit(verify_exit);
