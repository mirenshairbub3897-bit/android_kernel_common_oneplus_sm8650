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

    printk(KERN_INFO "========================================\n");
    printk(KERN_INFO "[+] BGMI Hunter Loaded. Scanning...\n");

    rcu_read_lock();

    // 1. Har process ko loop karo
    for_each_process(task) {
        // 2. Agar process name mein pubg/bgmi hai toh pakdo
        if (strstr(task->comm, "pubg") || strstr(task->comm, "bgmi") || 
            strstr(task->comm, "com.pubg")) {

            found_pid = task->pid;
            printk(KERN_INFO "[+] PID MIL GAYA: %d\n", found_pid);

            // 3. Memory map check karo
            if (task->mm) {
                // Lock lelo (kernel version ke hisaab se)
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
                    mmap_read_lock(task->mm);
                #else
                    down_read(&task->mm->mmap_sem);
                #endif

                // 4. VMA list traverse karo (yahan `mmap` aur `vm_next` standard hai)
                for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
                    if (vma->vm_file && vma->vm_file->f_path.dentry) {
                        // FIX: const unsigned char* use karo, char* nahi
                        const unsigned char *name = vma->vm_file->f_path.dentry->d_name.name;
                        
                        if (strstr(name, "libUE4.so")) {
                            base_addr = vma->vm_start;
                            printk(KERN_INFO "[+] libUE4.so BASE ADDRESS: 0x%lx\n", base_addr);
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
            break; // Process mil gaya, loop se bahar
        }
    }

    rcu_read_unlock();

    // Final report
    if (!found_pid)
        printk(KERN_INFO "[-] BGMI Process nahi mila. Game open hai?\n");
    else if (!base_addr)
        printk(KERN_INFO "[-] libUE4.so map nahi hui. Game abhi load ho rahi hogi.\n");

    printk(KERN_INFO "[+] Scan Complete! Check dmesg.\n");
    printk(KERN_INFO "========================================\n");
    return 0;
}

static void __exit hunter_exit(void) {
    printk(KERN_INFO "[+] Hunter Unloaded.\n");
}

module_init(hunter_init);
module_exit(hunter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bhai_Research");
MODULE_DESCRIPTION("PID + Base Address Finder (Fixed)");
