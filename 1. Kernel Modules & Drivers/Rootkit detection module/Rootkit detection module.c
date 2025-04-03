// Filename: advanced_rootkit_detector.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hidden.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define MODULE_NAME "adv_rootkit_detector"
#define HASH_ALGORITHM "sha256"

static unsigned long sys_call_table_addr;
static unsigned long *_sys_call_table;
static unsigned long kernel_text_start;
static unsigned long kernel_text_end;

struct module_hash {
    char name[MODULE_NAME_LEN];
    char hash[65]; // SHA256 hex string
    struct list_head list;
};

static LIST_HEAD(trusted_modules);

// Cryptographic context for module hashing
static struct crypto_shash *tfm;

// Function to calculate SHA256 hash
static int calculate_hash(const void *data, unsigned int len, char *output) {
    struct shash_desc *desc;
    int ret;
    
    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) return -ENOMEM;
    
    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret) goto out;
    
    ret = crypto_shash_update(desc, data, len);
    if (ret) goto out;
    
    ret = crypto_shash_final(desc, output);
out:
    kfree(desc);
    return ret;
}

// Verify module integrity
static int verify_module(struct module *mod) {
    char calculated_hash[32];
    struct module_hash *trusted;
    int ret = -ENOENT;
    
    list_for_each_entry(trusted, &trusted_modules, list) {
        if (strcmp(mod->name, trusted->name) == 0) {
            ret = calculate_hash(mod->core_layout.base, 
                                mod->core_layout.size, 
                                calculated_hash);
            if (memcmp(calculated_hash, trusted->hash, 32) != 0) {
                printk(KERN_ALERT "Module %s has been modified!\n", mod->name);
                return -EINVAL;
            }
            return 0;
        }
    }
    return -ENOENT;
}

// Check syscall table integrity
static void check_syscall_table(void) {
    int i;
    unsigned long addr;
    
    for (i = 0; i < NR_syscalls; i++) {
        addr = _sys_call_table[i];
        if (addr < kernel_text_start || addr > kernel_text_end) {
            printk(KERN_ALERT "Syscall %d hooked at %p\n", i, (void *)addr);
        }
    }
}

// Check hidden processes
static void check_hidden_processes(void) {
    struct task_struct *task;
    struct pid *pid;
    
    rcu_read_lock();
    for_each_process(task) {
        pid = get_pid(task->thread_pid);
        if (!pid_has_task(pid, PIDTYPE_PID)) {
            printk(KERN_ALERT "Hidden process detected: %d (%s)\n",
                   task->pid, task->comm);
        }
        put_pid(pid);
    }
    rcu_read_unlock();
}

// ProcFS interface
static int proc_show(struct seq_file *m, void *v) {
    struct module *mod;
    
    seq_printf(m, "Loaded Modules:\n");
    list_for_each_entry(mod, &modules, list) {
        seq_printf(m, "%-20s 0x%lx\n", mod->name, mod->core_layout.base);
    }
    
    return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Initialize detection module
static int __init detector_init(void) {
    struct module *mod;
    
    // Initialize crypto
    tfm = crypto_alloc_shash(HASH_ALGORITHM, 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ALERT "Failed to load crypto module\n");
        return PTR_ERR(tfm);
    }
    
    // Get kernel symbols
    sys_call_table_addr = kallsyms_lookup_name("sys_call_table");
    kernel_text_start = kallsyms_lookup_name("_stext");
    kernel_text_end = kallsyms_lookup_name("_etext");
    _sys_call_table = (unsigned long *)sys_call_table_addr;
    
    // Create proc entry
    proc_create("adv_rootkit_detector", 0, NULL, &proc_fops);
    
    // Perform system checks
    check_syscall_table();
    check_hidden_processes();
    
    // Verify loaded modules
    list_for_each_entry(mod, &modules, list) {
        if (verify_module(mod) != 0) {
            printk(KERN_WARNING "Untrusted module: %s\n", mod->name);
        }
    }
    
    printk(KERN_INFO "Advanced Rootkit Detector loaded\n");
    return 0;
}

static void __exit detector_exit(void) {
    remove_proc_entry("adv_rootkit_detector", NULL);
    crypto_free_shash(tfm);
    printk(KERN_INFO "Advanced Rootkit Detector unloaded\n");
}

module_init(detector_init);
module_exit(detector_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ethical Security Researcher");
MODULE_DESCRIPTION("Advanced Rootkit Detection Module");
MODULE_VERSION("1.0");
