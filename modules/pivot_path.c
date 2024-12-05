// sudo dmesg -C && sudo rmmod pivot_path.ko ; ../build-modules-native.sh pivot_path.o && sudo insmod pivot_path.ko && sudo dmesg

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>

#define MAX_PIVOTS 100
#define MAX_PATH_LEN 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Path Traversal Detection");



static char **path_pivots;
static int num_pivots = 0;


static void free_pivot_paths(void);
static int load_pivot_paths(const char *filepath);

int problematic_path(const char *path);
void remove_substring(char *str, const char *sub);


static int load_pivot_paths(const char *filepath) {
    struct file *f;
    char *buf;
    ssize_t read_bytes;
    loff_t pos = 0;
    int i = 0;

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL); // Allocate a buffer for reading
    if (!buf) {
        pr_err("Failed to allocate memory for pivot buffer\n");
        return -ENOMEM;
    }

    f = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(f)) {
        pr_err("Failed to open pivot file: %s\n", filepath);
        kfree(buf);
        return PTR_ERR(f);
    }

    while ((read_bytes = kernel_read(f, buf, PAGE_SIZE - 1, &pos)) > 0) {
        buf[read_bytes] = '\0'; // Null-terminate the read data
        char *line, *context;
        line = strsep(&buf, "\n");
        while (line && i < MAX_PIVOTS) {
            path_pivots[i] = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
            if (!path_pivots[i]) {
                pr_err("Failed to allocate memory for pivot path\n");
                filp_close(f, NULL);
                kfree(buf);
                return -ENOMEM;
            }
            strncpy(path_pivots[i], line, MAX_PATH_LEN - 1);
            path_pivots[i][MAX_PATH_LEN - 1] = '\0'; // Ensure null-termination
            num_pivots++;
            i++;
            line = strsep(&buf, "\n");
        }
    }

    filp_close(f, NULL);
    kfree(buf);
    return 0;
}

static void free_pivot_paths(void) {
    for (int i = 0; i < num_pivots; i++) {
        kfree(path_pivots[i]);
    }
    kfree(path_pivots);
}


void remove_substring(char *str, const char *sub) {
    size_t str_len, sub_len;
    char *pos;

    if (!str || !sub)
        return;

    str_len = strlen(str);
    sub_len = strlen(sub);

    if (sub_len == 0 || sub_len > str_len)
        return;

    while ((pos = strstr(str, sub)) != NULL) {
        // Shift the rest of the string left
        size_t tail_len = str_len - (pos - str) - sub_len;
        memmove(pos, pos + sub_len, tail_len + 1);
        str_len -= sub_len;
    }
}


int problematic_path(const char *path) {
    char *path_copy;
    char *token;
    char *rest;
    int counter, i;
    // remove all the pivots from the `path`
    for (i = 0; i< num_pivots; i++) {
        
    }

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
            }
        } else if (strcmp(token, ".") == 0) {
        } else if (*token != '\0' || *token != ' ') {
            counter++;
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
    if(strstr(filename,"war")) pr_info("[Debug] file: %s\n",filename);
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
    int ret;

    // Allocate memory for pivot path storage
    path_pivots = kmalloc(sizeof(char *) * MAX_PIVOTS, GFP_KERNEL);
    if (!path_pivots) {
        pr_err("Failed to allocate memory for pivot paths\n");
        return -ENOMEM;
    }

    // Load pivot paths from configuration file
    ret = load_pivot_paths("pivot.cfg");
    if (ret < 0) {
        kfree(path_pivots);
        return ret;
    }

    ret = register_kprobe(&kp_do_sys_open);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        free_pivot_paths();
        return ret;
    }

    pr_info("Path Traversal detection module loaded.\n");
    return 0;
}

static void __exit path_traversal_detection_exit(void) {
    unregister_kprobe(&kp_do_sys_open);
    free_pivot_paths();
    pr_info("Path Traversal detection module unloaded.\n");
}

module_init(path_traversal_detection_init);
module_exit(path_traversal_detection_exit);
