#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/uaccess.h> // copy_from_user / access_ok के लिए

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel_Verifier");

// आपके द्वारा दिए गए लाइव ऑफसेट्स
#define GNAME_OFFSET   0xdf74800
#define GWORLD_OFFSET  0xe4f28c0
#define VMATRIX_OFFSET 0xe4c9ff0
#define GUOBJECT_OFFSET 0xe22f8d0

static int __init verify_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found_pid = 0;
    unsigned long base_addr = 0;

    printk(KERN_INFO "[Verifier] Starting Kernel-Level Verification... \n");

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

    // 4. लाइव मेमोरी वेरिफिकेशन (Safe Memory Reading)
    // कर्नल स्पेस से गेम की यूजरस्पेस मेमोरी सुरक्षित पढ़ने के लिए kthread_use_mm का उपयोग किया जाता है
    kthread_use_mm(mm);

    unsigned long target_ptr = 0;
    float matrix_test[4] = {0};

    // क) GWorld वेरिफिकेशन टेस्ट
    unsigned long gworld_addr = base_addr + GWORLD_OFFSET;
    if (copy_from_user(&target_ptr, (void __user *)gworld_addr, sizeof(target_ptr)) == 0) {
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
    if (copy_from_user(&target_ptr, (void __user *)guobject_addr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GUObject (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", guobject_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GUObject (0x%lx) -> INVALID/NULL POINTER: 0x%lx [MISMATCH/OUTDATED]\n", guobject_addr, target_ptr);
        }
    }

    // ग) VMatrix वेरिफिकेशन टेस्ट (Matrix में आमतौर पर 0 और 1 के फ्लोट नंबर्स होते हैं)
    unsigned long vmatrix_addr = base_addr + VMATRIX_OFFSET;
    if (copy_from_user(&matrix_test, (void __user *)vmatrix_addr, sizeof(matrix_test)) == 0) {
        printk(KERN_INFO "[Verifier] VMatrix (0x%lx) Live Values: %f, %f, %f, %f\n", vmatrix_addr, matrix_test[0], matrix_test[1], matrix_test[2], matrix_test[3]);
    }

    kthread_unuse_mm(mm);
    mmput(mm);
    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[Verifier] Verification Module Unloaded.\n");
}

module_init(verify_init);
module_exit(verify_exit);
