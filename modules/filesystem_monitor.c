#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/kprobes.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("File System Monitoring Module");
MODULE_SOFTDEP("pre: netfilter_monitor");



#define ENV_BUFFER_SIZE 4096
#define BUF_SIZE 512

extern struct list_head captured_ports;
extern spinlock_t ports_lock;

struct port_entry {
    u16 port;
    atomic_t refcount;
    struct list_head list;
};


int problematic_path(const char *path);
static int read_path_pivots(char* file_path);
void do_the_magic(char* path);

void extract_path_variables(char *envp);


char ** path_pivots;
int path_pivots_count;
char ** path_variables;
int path_variables_count;
static char *f_path = NULL;

module_param(f_path, charp, 0644);
MODULE_PARM_DESC(f_path, "Path to the file containing paths to monitor");

static bool port_in_list(u16 port, struct list_head *ports_list)
{
    struct port_entry *entry;
    
    list_for_each_entry(entry, ports_list, list) {
        if (entry->port == port)
            return true;
    }
    return false;
}
static struct list_head *get_process_ports(struct task_struct *task){
    struct files_struct *files;
    struct fdtable *fdt;
    int i;
    struct list_head *ports_list;
    
    // Allocate the list head
    ports_list = kmalloc(sizeof(*ports_list), GFP_KERNEL);
    if (!ports_list)
        return NULL;
    INIT_LIST_HEAD(ports_list);

    files = task->files;
    if (!files) {
        kfree(ports_list);
        return NULL;
    }
    rcu_read_lock();
    fdt = files_fdtable(files);
    for (i = 0; i < fdt->max_fds; i++) {
        struct file *file;
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
            file = fdt->fd[i];
        #else
            file = fcheck_files(files, i);
        #endif
        if (!file)
            continue;

        if (S_ISSOCK(file_inode(file)->i_mode)) {
            struct socket *sock = file->private_data;
            struct sock *sk = sock->sk;

            if (sk->sk_family == AF_INET || sk->sk_family == AF_INET6) {
                if ((sk->sk_state == TCP_LISTEN) || 
                    (sk->sk_family == AF_INET && sk->sk_state != TCP_CLOSE)) {
                    __be16 port;
                    struct port_entry *new_port;
                    
                    if (sk->sk_family == AF_INET)
                        port = inet_sk(sk)->inet_sport;
                    else
                        port = inet_sk(sk)->inet_sport;

                    // Create new port entry
                    new_port = kmalloc(sizeof(*new_port), GFP_ATOMIC);
                    if (!new_port)
                        continue;
                    
                    new_port->port = ntohs(port);
                    atomic_set(&new_port->refcount, 1);
                    list_add_tail(&new_port->list, ports_list);
                }
            }
        }
    }
    rcu_read_unlock();

    return ports_list;
}

// Helper function to free the ports list
static void free_ports_list(struct list_head *ports_list)
{
    struct port_entry *entry, *tmp;
    
    list_for_each_entry_safe(entry, tmp, ports_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    kfree(ports_list);
}

void check_ports(struct task_struct *task) {
    struct port_entry *entry, *tmp;
    struct list_head *listening_ports;
    listening_ports = get_process_ports(task);

    spin_lock(&ports_lock);
    list_for_each_entry_safe(entry, tmp, &captured_ports, list) {
        if (port_in_list(entry->port, listening_ports)) {
            pr_warn("[bluerock.io filesystem_monitor] Path traversal detected by PID %d on port %d\n", task->pid, entry->port);
            list_del(&entry->list);
            kfree(entry);
            break;
        }
    }
    spin_unlock(&ports_lock);
}

void extract_path_variables(char __user *envp) {
    char **result = NULL;
    int count = 0;
    char *env = NULL;
    char *value = NULL;
    int ret;

    if (!envp) {
        pr_err("[bluerock.io filesystem_monitor] Invalid environment pointer\n");
        return;
    }

    while (1) {
        env = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!env) {
            pr_err("[bluerock.io filesystem_monitor] Memory allocation failed for environment variable buffer\n");
            while (count--)
                kfree(result[count]);
            kfree(result);
            return;
        }
        ret = copy_from_user(env, envp, PAGE_SIZE);
        if (ret < 0) {
            pr_err("[bluerock.io filesystem_monitor] Failed to copy environment variable from user space\n");
            kfree(env);
            break;
        }
        pr_info("[bluerock.io filesystem_monitor] [raw]: %s\n",env);

        env[PAGE_SIZE - 1] = '\0';

        if (env[0] == '\0') {
            kfree(env);
            break;
        }

        value = strchr(env, '=');
        if (!value || value[1] == '\0') {
            kfree(env);
            envp += strlen(env) + 1;
            continue;
        }
        value++;
        
        if (value[0] == '/' || strstr(value, "/")) {
            char **new_result = krealloc(result, sizeof(char *) * (count + 2), GFP_KERNEL);
            if (!new_result) {
                pr_err("[bluerock.io filesystem_monitor] Memory allocation failed for result array\n");
                kfree(env);
                while (count--)
                    kfree(result[count]);
                kfree(result);
                return;
            }
            result = new_result;

            result[count] = kstrdup(value, GFP_KERNEL);
            if (!result[count]) {
                pr_err("[bluerock.io filesystem_monitor] Memory allocation failed for path value\n");
                kfree(env);
                while (count--)
                    kfree(result[count]);
                kfree(result);
                return;
            }
            count++;
        }

        kfree(env);
        envp += strlen(env) + 1;
    }

    if (result) {
        result[count] = NULL;
    }

    path_variables_count = count;
    path_variables = result;
}

static int read_path_pivots(char* file_path){
    struct file *file;
    char *buffer, *line;
    size_t read_bytes;
    loff_t offset = 0;
    int count = 0;
    char **list = NULL;

    file = filp_open(file_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("[bluerock.io filesystem_monitor] Failed to open file: %s\n", file_path);
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
                    pr_err("[bluerock.io filesystem_monitor] Memory allocation failed\n");
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
    int ret;

    mm = current->mm; // Get the memory descriptor of the current thread
    if (!mm) {
        pr_err("[bluerock.io filesystem_monitor] Failed to get mm_struct\n");
        return NULL;
    }

    env_start = mm->env_start; // Start of the environment variables
    env_end = mm->env_end;     // End of the environment variables
    if( env_end - env_start < 1) return NULL;

    // Allocate a buffer to copy environment variables
    buffer = kmalloc(ENV_BUFFER_SIZE, GFP_KERNEL);
    if (!buffer) {
        pr_err("[bluerock.io filesystem_monitor] Failed to allocate buffer for environment variables\n");
        return NULL;
    }

    // Copy the environment variables to the buffer
    pr_info("[bluerock.io filesystem_monitor] env_start = %lx",env_start);
    extract_path_variables((char __user *)env_start);
    pr_info("[bluerock.io filesystem_monitor] variables count: %d\n",path_variables_count);
    for (int i = 0; i< path_variables_count; i++){
        pr_info("[bluerock.io filesystem_monitor] ENV[%d]: %s\n",i, path_variables[i]);
    }
    ret = copy_from_user(buffer, (void __user *)env_start, ENV_BUFFER_SIZE);
    if (ret < 0) {
        pr_err("[bluerock.io filesystem_monitor] Failed to copy environment variables from user space\n");
        kfree(buffer);
        return NULL;
    }

    env_area = buffer;
    while ((env_ptr = strsep(&env_area, "\0")) != NULL) {
        if (strncmp(env_ptr, "PATH=", 5) == 0) {
            path_value = kmalloc(strlen(env_ptr) + 1, GFP_KERNEL);
            if (!path_value) {
                pr_err("[bluerock.io filesystem_monitor] Failed to allocate memory for PATH value\n");
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
    // pr_info("[bluerock.io filesystem_monitor] Filename after magic: %s\n",filename);
    // if(strstr(filename,"war")) pr_info("[bluerock.io filesystem_monitor] [Debug] file: %s\n",filename);
    check_ports(current);
    if (!problematic_path(filename)){
        char *path_env = get_path_env();
        
        if (path_env) {
            pr_info("[bluerock.io filesystem_monitor] Thread PATH: %s\n", path_env);
            kfree(path_env);
        } else {
            // pr_info("[bluerock.io filesystem_monitor] Failed to retrieve PATH\n");
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
        pr_err("[bluerock.io filesystem_monitor] Please provide configration\n");
        return -1;
    }
    // check if the module that initiliased capture_ports is loaded or not
    if (!captured_ports.next || !captured_ports.prev) {
        pr_err("[bluerock.io filesystem_monitor] Please load the netfilter_monitor module first\n");
        return -1;
    } 
    ret = register_kprobe(&kp_do_sys_open);
    if (ret < 0) {
        pr_err("[bluerock.io filesystem_monitor] Failed to register kprobe: %d\n", ret);
        return ret;
    }
    pr_info("[bluerock.io filesystem_monitor] File System Monitoring Module module loaded.\n");
    // reading the config
    read_path_pivots(f_path);
    pr_info("[bluerock.io filesystem_monitor] Config file loaded.\n");
    return 0;
}

static void __exit path_traversal_detection_exit(void) {
    unregister_kprobe(&kp_do_sys_open);
    for (int i = 0; i < path_pivots_count; i++) {
        kfree(path_pivots[i]);
    }
    kfree(path_pivots);
    pr_info("[bluerock.io filesystem_monitor] File System Monitoring Module module unloaded.\n");
}

module_init(path_traversal_detection_init);
module_exit(path_traversal_detection_exit);
