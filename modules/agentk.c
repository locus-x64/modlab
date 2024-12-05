#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/sched/signal.h>

void reset_signal_count(struct timer_list *t);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("AgentK for ASLR Bruteforce Detection");

static int sig_fault_count = 0;
static int threshold = 10;   // threshold for signal count in time frame
static int time_window = 10; // time window in seconds
static char monitored_thread_name[TASK_COMM_LEN] = ""; // Thread name to monitor
static int monitored_parent_pid = 0; // Parent PID to monitor
static struct timer_list signal_timer;

static int problematic_signals[] = {SIGSEGV};

static int is_problematic_signal(int sig) {
    for (int i = 0; i < sizeof(problematic_signals) / sizeof(int); i++) {
        if (problematic_signals[i] == sig) {
            return 1;
        }
    }
    return 0;
}

void reset_signal_count(struct timer_list *t) {
    if (sig_fault_count > threshold) {
        pr_alert("Signal spike detected: %d signals in %d seconds\n", sig_fault_count, time_window);
        if (strlen(monitored_thread_name) > 0) {
            printk(KERN_INFO "Thread with repeated signals: %s\n", monitored_thread_name);
        }
    }
    sig_fault_count = 0;
    memset(monitored_thread_name, 0, sizeof(monitored_thread_name));
    mod_timer(&signal_timer, jiffies + msecs_to_jiffies(time_window * 1000)); // Reset timer
}

static int pre_handler_send_signal_locked(struct kprobe *p, struct pt_regs *regs) {
    int sig = (int)regs->di; // Signal number is usually the first argument
    char current_thread_name[TASK_COMM_LEN];
    char parent_thread_name[TASK_COMM_LEN];
    struct task_struct *task = current;
    int parent_pid = task->parent->pid;

    if (is_problematic_signal(sig)) {
        sig_fault_count++;

        get_task_comm(current_thread_name, task);


        if (strcmp (monitored_thread_name, current_thread_name) == 0 
                    && parent_pid == monitored_parent_pid) {
            // printk(KERN_INFO "Repeated signal to thread: %s with PPID: %d\n", current_thread_name, parent_pid);
            if (sig_fault_count > threshold) {
                get_task_comm(parent_thread_name, task->parent);
                pr_alert("Signal spike detected: %d signals in %d seconds\n", sig_fault_count, time_window);
                pr_info("Thread with repeated signals: %s: %d and parent: (%s,%d)\n", monitored_thread_name, current->pid, parent_thread_name, monitored_parent_pid);
            }
        } else {
            strncpy(monitored_thread_name, current_thread_name, TASK_COMM_LEN);
            monitored_parent_pid = parent_pid;
        }
    }

    return 0;
}


static struct kprobe kp_send_signal = {
    .symbol_name = "send_signal_locked",
    .pre_handler = pre_handler_send_signal_locked,
};

static int __init agentk_init(void) {
    int ret;

    timer_setup(&signal_timer, reset_signal_count, 0);
    mod_timer(&signal_timer, jiffies + msecs_to_jiffies(time_window * 1000));

    ret = register_kprobe(&kp_send_signal);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe for send_signal_locked: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "AgentK loaded.\n");
    return 0;
}

static void __exit agentk_exit(void) {
    del_timer(&signal_timer);
    unregister_kprobe(&kp_send_signal);
    printk(KERN_INFO "AgentK unloaded.\n");
}

module_init(agentk_init);
module_exit(agentk_exit);