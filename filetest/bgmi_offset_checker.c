#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel_Verifier_V4");

#define GNAME_OFFSET   0xdf74800
#define GWORLD_OFFSET  0xe4f28c0
#define VMATRIX_OFFSET 0xe4c9ff0
#define GUOBJECT_OFFSET 0xe22f8d0

// कर्नल का सबसे अचूक और डायरेक्ट मैमोरी रीडर (VFS Based)
static int direct_kernel_read(int pid, unsigned long addr, void *buf, int len) {
    struct file *file;
    char path[64];
    loff_t pos = addr;
    ssize_t bytes_read;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    file = filp_open(path, O_RDONLY | O_LARGEFILE, 0);
    
    if (IS_ERR(file)) {
        return -1;
    }

    // कर्नल डायरेक्ट खुद ही फाइल सिस्टम लेवल से गेम की रैम को पढ़ लेता है
    bytes_read = kernel_read(file, buf, len, &pos);
    filp_close(file, NULL);

    return (bytes_read == len) ? 0 : -1;
}

static int __init verify_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found_pid = 0;
    unsigned long base_addr = 0;

    printk(KERN_INFO "[Verifier] Starting VFS Kernel Verification... \n");

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

    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "[Verifier] Error: Failed to access mm_struct.\n");
        return -EINVAL;
    }

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

    mmput(mm);

    if (base_addr == 0) {
        printk(KERN_ERR "[Verifier] Error: libUE4.so base address not found!\n");
        return -ENOENT;
    }

    printk(KERN_INFO "[Verifier] Target Base Address: 0x%lx\n", base_addr);

    unsigned long target_ptr = 0;
    unsigned int matrix_bytes = 0;

    // क) GWorld टेस्ट
    unsigned long gworld_addr = base_addr + GWORLD_OFFSET;
    if (direct_kernel_read(found_pid, gworld_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GWorld (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", gworld_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GWorld (0x%lx) -> INVALID POINTER: 0x%lx [MISMATCH]\n", gworld_addr, target_ptr);
        }
    } else {
        printk(KERN_ERR "[Verifier] GWorld Read Failed.\n");
    }

    // ख) GUObject टेस्ट
    unsigned long guobject_addr = base_addr + GUOBJECT_OFFSET;
    if (direct_kernel_read(found_pid, guobject_addr, &target_ptr, sizeof(target_ptr)) == 0) {
        if (target_ptr != 0 && target_ptr > 0x1000000000) {
            printk(KERN_INFO "[Verifier] GUObject (0x%lx) -> VALID POINTER: 0x%lx [MATCH]\n", guobject_addr, target_ptr);
        } else {
            printk(KERN_WARNING "[Verifier] GUObject (0x%lx) -> INVALID POINTER: 0x%lx [MISMATCH]\n", guobject_addr, target_ptr);
        }
    }

    // ग) VMatrix टेस्ट
    unsigned long vmatrix_addr = base_addr + VMATRIX_OFFSET;
    if (direct_kernel_read(found_pid, vmatrix_addr, &matrix_bytes, sizeof(matrix_bytes)) == 0) {
        printk(KERN_INFO "[Verifier] VMatrix (0x%lx) Raw Value: 0x%x\n", vmatrix_addr, matrix_bytes);
    }

    return 0;
}

static void __exit verify_exit(void) {
    printk(KERN_INFO "[Verifier] Verification Module Unloaded.\n");
}

module_init(verify_init);
module_exit(verify_exit);
