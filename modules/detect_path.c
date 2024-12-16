// sudo dmesg -C && sudo rmmod detect_path.ko ; ../build-modules-native.sh detect_path.o && sudo insmod detect_path.ko && sudo dmesg

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>


#define ENV_BUFFER_SIZE 4096
#define BUF_SIZE 512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Path Traversal Detection");

int problematic_path(const char *path);
static int read_path_pivots(char* file_path);
void do_the_magic(char* path);


char ** path_pivots;
int path_pivots_count;
static char *f_path = NULL;

module_param(f_path, charp, 0644);
MODULE_PARM_DESC(f_path, "Path to the file containing paths to monitor");


static int read_path_pivots(char* file_path){
    struct file *file;
    char *buffer, *line;
    size_t read_bytes;
    loff_t offset = 0;
    int count = 0;
    char **list = NULL;

    file = filp_open(file_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("Failed to open file: %s\n", file_path);
        return PTR_ERR(file);
    }

    buffer = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!buffer) {
        filp_close(file, NULL);
        return -ENOMEM;
    }

    while ((read_bytes = kernel_read(file, buffer, BUF_SIZE - 1, &offset)) > 0) {
        buffer[read_bytes] = '\0';  // Null-terminate the read buffer
        line = buffer;

        while ((line = strsep(&buffer, "\n")) != NULL) {
            size_t len = strlen(line);
            if (len > 0) {
                char **new_list = krealloc(list, (count + 1) * sizeof(char *), GFP_KERNEL);
                if (!new_list) {
                    pr_err("Memory allocation failed\n");
                    kfree(buffer);
                    kfree(list);
                    filp_close(file, NULL);
                    return -ENOMEM;
                }
                list = new_list;
                list[count] = kstrdup(line, GFP_KERNEL);
                if (!list[count]) {
                    kfree(buffer);
                    kfree(list);
                    filp_close(file, NULL);
                    return -ENOMEM;
                }
                count++;
            }
        }
    }

    filp_close(file, NULL);
    kfree(buffer);

    path_pivots = list;
    path_pivots_count = count;
    return 0;
}
void do_the_magic(char* path){
    int i;
    for (i = 0; i < path_pivots_count; i++) {
        size_t len = strlen(path_pivots[i]);
        if (strncmp(path, path_pivots[i], len) == 0) {
            memmove(path, path + len, strlen(path + len) + 1);
            break;  // Only remove the first matching prefix
        }
    }
}


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

static char *get_path_env(void) {
    struct mm_struct *mm;
    char *env_area, *env_ptr, *path_value = NULL;
    unsigned long env_start, env_end;
    char *buffer;

    mm = current->mm; // Get the memory descriptor of the current thread
    if (!mm) {
        pr_err("Failed to get mm_struct\n");
        return NULL;
    }

    env_start = mm->env_start; // Start of the environment variables
    env_end = mm->env_end;     // End of the environment variables
    if( env_end - env_start < 1) return NULL;

    // Allocate a buffer to copy environment variables
    buffer = kmalloc(ENV_BUFFER_SIZE, GFP_KERNEL);
    if (!buffer) {
        pr_err("Failed to allocate buffer for environment variables\n");
        return NULL;
    }

    // Copy the environment variables to the buffer
    pr_info("env_start = %lx",env_start);
    if (copy_from_user(buffer, (void __user *)env_start, ENV_BUFFER_SIZE)) {
        pr_err("Failed to copy environment variables from user space\n");
        kfree(buffer);
        return NULL;
    }

    env_area = buffer;
    while ((env_ptr = strsep(&env_area, "\0")) != NULL) {
        if (strncmp(env_ptr, "PATH=", 5) == 0) {
            path_value = kmalloc(strlen(env_ptr) + 1, GFP_KERNEL);
            if (!path_value) {
                pr_err("Failed to allocate memory for PATH value\n");
                kfree(buffer);
                return NULL;
            }
            strcpy(path_value, env_ptr + 5); // Extract the PATH value
            break;
        }
    }

    kfree(buffer);
    return path_value; // Caller must free this
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

    do_the_magic(filename);
    // pr_info("Filename after magic: %s\n",filename);
    if(strstr(filename,"war")) pr_info("[Debug] file: %s\n",filename);
    if (!problematic_path(filename)){
        char *path_env = get_path_env();
        
        if (path_env) {
            pr_info("Thread PATH: %s\n", path_env);
            kfree(path_env);
        } else {
            // pr_info("Failed to retrieve PATH\n");
        }

        kfree(path_env);
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
    if (f_path == NULL ){
        pr_err("Please provide configration\n");
        return -1;
    }
    ret = register_kprobe(&kp_do_sys_open);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
    }
    pr_info("Path Traversal detection module loaded.\n");
    // reading the config
    read_path_pivots(f_path);
    pr_info("Config file loaded.\n");
    return 0;
}

static void __exit path_traversal_detection_exit(void) {
    unregister_kprobe(&kp_do_sys_open);
    for (int i = 0; i < path_pivots_count; i++) {
        kfree(path_pivots[i]);
    }
    kfree(path_pivots);
    pr_info("Path Traversal detection module unloaded.\n");
}

module_init(path_traversal_detection_init);
module_exit(path_traversal_detection_exit);
