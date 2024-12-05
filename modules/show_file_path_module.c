// sudo dmesg -C && sudo rmmod show_file_path_module.ko ; ../build-modules-native.sh show_file_path_module.o && sudo insmod show_file_path_module.ko && sudo dmesg

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Path Traversal Detection");

#define MAX_PATH_DEPTH 1024



// Pre-handler to check for path traversal
static int pre_handler_do_sys_open(struct kprobe *p, struct pt_regs *regs) {
    char __user *filename_user = (char __user *)regs->si;
    char filename[256];
    // pr_info("Inside syscall\n");

    // Copy filename from user space
    ssize_t ret = strncpy_from_user(filename, filename_user, sizeof(filename) - 1);
    if (ret < 0) {
        pr_alert("Failed to copy filename from user space.\n");
        return 0;
    }
    filename[sizeof(filename) - 1] = '\0'; // Ensure null-termination
    if (strstr(filename, "..")) {
        pr_info("filename: %s\n",filename);
    }

    return 0;
}

// Kprobe setup
static struct kprobe kp_do_sys_open = {
    .symbol_name = "do_sys_openat2",
    .pre_handler = pre_handler_do_sys_open,
};

static int __init path_traversal_alert_init(void) {
    int ret = register_kprobe(&kp_do_sys_open);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
    }
    pr_info("Path Traversal Alert System loaded.\n");
    return 0;
}

static void __exit path_traversal_alert_exit(void) {
    unregister_kprobe(&kp_do_sys_open);
    pr_info("Path Traversal Alert System unloaded.\n");
}

module_init(path_traversal_alert_init);
module_exit(path_traversal_alert_exit);
