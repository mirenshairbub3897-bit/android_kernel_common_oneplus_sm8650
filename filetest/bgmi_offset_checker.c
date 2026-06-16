#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/version.h>

static int __init hunter_init(void) {
    struct task_struct *task;
    struct vm_area_struct *vma;
    int found_pid = 0;
    unsigned long base_addr = 0;

    // Kernel log mein print hoga (JHA SE RUN KARE, WAHI PE LOG)
    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "Kernel Hunter: BGMI Scan Start Kar Raha Hu...\n");

    // RCU lock safe traversal ke liye
    rcu_read_lock();
    
    // 1. Saare processes loop karo
    for_each_process(task) {
        // Agar process name mein "pubg" ya "bgmi" hai toh pakdo
        if (strstr(task->comm, "pubg") || strstr(task->comm, "bgmi") || 
            strstr(task->comm, "com.pubg")) {
            
            found_pid = task->pid;
            printk(KERN_INFO "[+] BGMI Process Mil Gaya! PID: %d\n", found_pid);
            
            // 2. Ab is process ka memory map (VMA) check karo
            if (task->mm) {
                // Kernel version ke hisaab se lock function (5.8+ ka alag hai)
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
                    mmap_read_lock(task->mm);
                #else
                    down_read(&task->mm->mmap_sem);
                #endif

                // Har VMA (memory region) loop karo
                for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                    if (vma->vm_file && vma->vm_file->f_path.dentry) {
                        char *name = vma->vm_file->f_path.dentry->d_name.name;
                        // Agar region ka naam libUE4.so hai toh base address yehi hai
                        if (strstr(name, "libUE4.so")) {
                            base_addr = vma->vm_start;
                            printk(KERN_INFO "[+] libUE4.so Base Address: 0x%lx\n", base_addr);
                            break;
                        }
                    }
                }

                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
                    mmap_read_unlock(task->mm);
                #else
                    up_read(&task->mm->mmap_sem);
                #endif
            }
            break; // Mil gaya toh loop se bahar
        }
    }
    rcu_read_unlock();

    // Agar nahi mila toh log bhejo
    if (!found_pid) {
        printk(KERN_INFO "[-] BGMI Process Nahi Mila. Game Open Hai?\n");
    } else if (!base_addr) {
        printk(KERN_INFO "[-] libUE4.so Map Nahi Hui. Shayad Game Load ho rahi hai.\n");
    }

    printk(KERN_INFO "Kernel Hunter: Scan Complete!\n");
    printk(KERN_INFO "========================================\n");
    return 0;
}

static void __exit hunter_exit(void) {
    printk(KERN_INFO "Kernel Hunter: Module Unload Ho Gaya.\n");
}

module_init(hunter_init);
module_exit(hunter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhai_Security_Research");
MODULE_DESCRIPTION("Sirf PID aur Base Address dhoondne wala module (Educational)");
