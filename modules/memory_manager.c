#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lema Heri");
MODULE_DESCRIPTION("CSE330-Memory-Manager");

static int pid;
static unsigned long long addr;

module_param(pid, int, 0);
module_param(addr, ullong, 0);

static int __init memory_manager_init(void) {
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pgd_t *pgd = NULL;
    p4d_t *p4d = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    pte_t *pte = NULL;
    unsigned long physical_address = 0;
    swp_entry_t swp_entry = 0;
    unsigned long swp_val = 0;
    

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task || !task->mm) {
        printk(KERN_ERR "[CSE330-Memory-Manager] Invalid PID or process memory structure\n");
        return -EINVAL;
    }
    mm = task->mm;

    // page table walking
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        goto out;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
        goto out;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || unlikely(pud_bad(*pud)))
        goto out;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
        goto out;

    pte = pte_offset_kernel(pmd, addr);
    if (pte_present(*pte) == 0) {
        swp_entry = __pte_to_swp_entry(*pte);
        swp_val = swp_entry.val;

        printk(KERN_INFO "[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [N/A] swap identifier [%lx]\n",
           pid, addr,swp_val);
        goto out;
    }

    if (pte == NULL ) {
        printk(KERN_INFO "[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [N/A] swap identifier [N/A]\n",
           pid, addr);
        goto out;
    }

    // physical address
    physical_address = (pte_pfn(*pte) << PAGE_SHIFT) | (addr & ~PAGE_MASK);
    printk(KERN_INFO "[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [%lx] swap identifier [NA]\n",
           pid, addr, physical_address);

out:
    return 0;
}

static void __exit memory_manager_exit(void) {
    printk(KERN_INFO "[CSE330-Memory-Manager] Module unloaded\n");
}

module_init(memory_manager_init);
module_exit(memory_manager_exit);
