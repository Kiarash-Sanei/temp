#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("List all system calls - Experiment 8.1 - Kernel 6.1.159");

/*
 * در kernel 6.1 تابع kallsyms_lookup_name دیگر export نمی‌شود
 * از kprobes استفاده می‌کنیم تا آدرسش را پیدا کنیم
 */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;

static unsigned long *sct_addr = NULL;
static struct proc_dir_entry *proc_entry = NULL;

/* پیدا کردن kallsyms_lookup_name با kprobes */
static int find_kallsyms_lookup_name(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[-] register_kprobe failed: %d\n", ret);
        return ret;
    }

    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    printk(KERN_INFO "[+] kallsyms_lookup_name found at: 0x%lx\n",
           (unsigned long)my_kallsyms_lookup_name);
    return 0;
}

/* پیدا کردن آدرس sys_call_table */
static unsigned long *get_syscall_table(void)
{
    unsigned long *table;

    if (!my_kallsyms_lookup_name) {
        printk(KERN_ERR "[-] kallsyms_lookup_name not available\n");
        return NULL;
    }

    table = (unsigned long *)my_kallsyms_lookup_name("sys_call_table");
    if (!table) {
        printk(KERN_ERR "[-] Could not find sys_call_table\n");
        return NULL;
    }

    return table;
}

/* نمایش لیست syscall ها در /proc/syscalls */
static int syscall_proc_show(struct seq_file *m, void *v)
{
    unsigned long i;
    unsigned long nr_syscalls = 0;

    if (!sct_addr) {
        seq_printf(m, "Error: sys_call_table not found\n");
        return -EINVAL;
    }

    /* پیدا کردن تعداد syscall ها از NR_syscalls اگر تعریف شده */
#ifdef NR_syscalls
    nr_syscalls = NR_syscalls;
#else
    nr_syscalls = 450;
#endif

    seq_printf(m, "System Calls List (x86_64) - Kernel 6.1.159\n");
    seq_printf(m, "=============================================\n");
    seq_printf(m, "%-8s %-20s %s\n", "Syscall#", "Address", "Name");
    seq_printf(m, "%-8s %-20s %s\n", "--------", "-------", "----");

    for (i = 0; i < nr_syscalls; i++) {
        unsigned long addr = sct_addr[i];
        char sym_name[KSYM_NAME_LEN];

        /* پیدا کردن نام symbol */
        if (sprint_symbol_no_offset(sym_name, addr) <= 0)
            snprintf(sym_name, sizeof(sym_name), "unknown");

        seq_printf(m, "%-8lu 0x%016lx %s\n", i, addr, sym_name);
    }

    seq_printf(m, "\nTotal syscalls: %lu\n", nr_syscalls);

    return 0;
}

static int syscall_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_proc_show, NULL);
}

static const struct proc_ops proc_ops = {
    .proc_open    = syscall_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init syscall_list_init(void)
{
    int ret;

    printk(KERN_INFO "[+] Experiment 8.1: Loading...\n");

    /* مرحله 1: پیدا کردن kallsyms_lookup_name */
    ret = find_kallsyms_lookup_name();
    if (ret < 0)
        return ret;

    /* مرحله 2: پیدا کردن sys_call_table */
    sct_addr = get_syscall_table();
    if (!sct_addr)
        return -EFAULT;

    printk(KERN_INFO "[+] sys_call_table at: 0x%lx\n",
           (unsigned long)sct_addr);

    /* مرحله 3: ایجاد /proc/syscalls */
    proc_entry = proc_create("syscalls", 0444, NULL, &proc_ops);
    if (!proc_entry) {
        printk(KERN_ERR "[-] Failed to create /proc/syscalls\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "[+] Module loaded. Run: cat /proc/syscalls\n");
    return 0;
}

static void __exit syscall_list_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);

    printk(KERN_INFO "[-] Experiment 8.1: Unloaded\n");
}

module_init(syscall_list_init);
module_exit(syscall_list_exit);