#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h> // for_each_process के लिए
#include <linux/sched.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Auto_PID_Finder");

static int __init auto_test_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int found_pid = 0;

    printk(KERN_INFO "[AutoTest] Looking for BGMI process... \n");

    // 1. कर्नल की पूरी प्रोसेस लिस्ट में गेम को ऑटो-स्कैन करना
    rcu_read_lock();
    for_each_process(task) {
        // गेम का नाम या पैकेज पहचानना
        if (task->comm && (strstr(task->comm, "pubg.imobile") || strstr(task->comm, "UE4"))) {
            found_pid = task->pid;
            printk(KERN_INFO "[AutoTest] BGMI Auto-Found! Current PID = %d\n", found_pid);
            break; 
        }
    }
    rcu_read_unlock();

    if (found_pid == 0) {
        printk(KERN_ERR "[AutoTest] Error: BGMI is not running right now!\n");
        return -ESRCH; 
    }

    // 2. ऑटोमेटिक मिले PID की मेमोरी मैप्स में जाना
    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "[AutoTest] Error: Failed to access mm_struct (Memory map locked).\n");
        return -EINVAL;
    }

    // 3. बिना रुके libUE4.so का बेस एड्रेस स्कैन करना
    VMA_ITERATOR(vmi, mm, 0);
    for_each_vma(vmi, vma) {
        if (vma->vm_file) {
            char *filename = vma->vm_file->f_path.dentry->d_name.name;
            if (strcmp(filename, "libUE4.so") == 0) {
                // सीधे कर्नल लॉग्स में बेस एड्रेस भेज देना
                printk(KERN_INFO "[AutoTest] SUCCESS: libUE4.so Base Address = 0x%lx\n", vma->vm_start);
                break;
            }
        }
    }

    mmput(mm);
    return 0;
}

static void __exit auto_test_exit(void) {
    printk(KERN_INFO "[AutoTest] Module Unloaded.\n");
}

module_init(auto_test_init);
module_exit(auto_test_exit);
