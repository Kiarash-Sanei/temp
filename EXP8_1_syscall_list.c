#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/syscall.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("List all system calls - Experiment 8.1");

typedef long (*syscall_fn_t)(unsigned long, unsigned long, unsigned long, 
                              unsigned long, unsigned long, unsigned long);

static void** sys_call_table = NULL;
static struct proc_dir_entry *proc_entry = NULL;

static unsigned long get_syscall_table_addr(void)
{
    unsigned long addr = kallsyms_lookup_name("sys_call_table");
    if (!addr) {
        printk(KERN_ERR "[-] Could not find sys_call_table\n");
        return 0;
    }
    return addr;
}

static int syscall_proc_show(struct seq_file *m, void *v)
{
    unsigned long i;
    unsigned long table_addr;
    
    table_addr = get_syscall_table_addr();
    if (!table_addr) {
        seq_printf(m, "Error: Could not find syscall table\n");
        return -EINVAL;
    }
    
    sys_call_table = (void**)table_addr;
    
    seq_printf(m, "System Calls List (x86_64)\n");
    seq_printf(m, "==========================\n");
    seq_printf(m, "Syscall#\tAddress\t\t\tName\n");
    seq_printf(m, "--\t--------\t\t\t----\n");
    
    for (i = 0; i < NR_syscalls; i++) {
        const char *name = NULL;
        unsigned long addr = (unsigned long)sys_call_table[i];
        
        char buffer[256];
        name = kallsyms_lookup(addr, NULL, NULL, NULL, buffer);
        
        seq_printf(m, "%lu\t0x%lx\t%s\n", 
                   i, 
                   addr,
                   name ? name : "unknown");
    }
    
    seq_printf(m, "\nTotal syscalls: %lu\n", (unsigned long)NR_syscalls);
    
    return 0;
}

static int syscall_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_proc_show, NULL);
}

static const struct proc_ops proc_ops = {
    .proc_open = syscall_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init syscall_list_init(void)
{
    unsigned long addr;
    
    printk(KERN_INFO "[+] Experiment 8.1: Syscall List Module Loading...\n");
    
    addr = get_syscall_table_addr();
    if (!addr) {
        printk(KERN_ERR "[-] Failed to get syscall table address\n");
        return -EFAULT;
    }
    
    printk(KERN_INFO "[+] Found sys_call_table at: 0x%lx\n", addr);
    printk(KERN_INFO "[+] Total syscalls: %lu\n", (unsigned long)NR_syscalls);
    
    proc_entry = proc_create("syscalls", 0444, NULL, &proc_ops);
    if (!proc_entry) {
        printk(KERN_ERR "[-] Failed to create /proc/syscalls\n");
        return -ENOMEM;
    }
    
    printk(KERN_INFO "[+] Module loaded successfully\n");
    printk(KERN_INFO "[+] Read syscalls with: cat /proc/syscalls\n");
    
    return 0;
}

static void __exit syscall_list_exit(void)
{
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    printk(KERN_INFO "[-] Experiment 8.1: Syscall List Module Unloaded\n");
}

module_init(syscall_list_init);
module_exit(syscall_list_exit);
