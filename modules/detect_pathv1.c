// sudo dmesg -C && sudo rmmod detect_path.ko ; ../build-modules-native.sh detect_path.o && sudo insmod detect_path.ko && sudo dmesg

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Path Traversal Detection");

int problematic_path(const char *path);

int problematic_path(const char *path) {
    char *path_copy;
    char *token;
    char *rest;
    int counter;
    
    
    path_copy = kmalloc(strlen(path) + 1, GFP_KERNEL);
    if (!path_copy) {
        printk(KERN_ERR "Failed to allocate memory for path copy\n");
        return -ENOMEM;
    }
    strcpy(path_copy, path);

    rest = path_copy;
    counter = 0;
    token = strsep(&rest, "/");

    while ((token = strsep(&rest, "/")) != NULL) {
        if (strcmp(token, "..") == 0) {
            if (counter > 0) {
                counter--;
                // pr_info("----- Pop");
            }
        } else if (strcmp(token, ".") == 0) {
        } else if (*token != '\0' || *token != ' ') {
            counter++;
            // pr_info("----- Push");
        }

        if (counter == 0) {
            kfree(path_copy);
            return 0;
        }
    }

    kfree(path_copy);
    return 1;
}


static int pre_handler_do_sys_open(struct kprobe *p, struct pt_regs *regs) {
    char __user *filename_user = (char __user *)regs->si;
    char filename[256];
    ssize_t ret;
    if(filename_user != NULL) ret = strncpy_from_user(filename, filename_user, sizeof(filename) - 1);
    if (ret < 0) {
        return 0;
    }
    filename[sizeof(filename) - 1] = '\0';
    if(strstr(filename,"ali")) pr_info("[Debug] file: %s\n",filename);
    if (!problematic_path(filename)){
        pr_alert("Path traversal attempt detected: %s\n", filename);
    
    }

    return 0;
}

static struct kprobe kp_do_sys_open = {
    .symbol_name = "do_sys_openat2",
    .pre_handler = pre_handler_do_sys_open,
};

static int __init path_traversal_detection_init(void) {
    int ret = register_kprobe(&kp_do_sys_open);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
    }
    pr_info("Path Traversal detection module loaded.\n");
    return 0;
}

static void __exit path_traversal_detection_exit(void) {
    unregister_kprobe(&kp_do_sys_open);
    pr_info("Path Traversal detection module unloaded.\n");
}

module_init(path_traversal_detection_init);
module_exit(path_traversal_detection_exit);
