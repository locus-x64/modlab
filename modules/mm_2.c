#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/mm.h>

unsigned int find_phys_addr(unsigned int user_pid, unsigned long long user_addr);
static unsigned long long addr;
static unsigned int pid;


module_param(addr, ullong, 0);
module_param(pid, uint, 0);

unsigned int find_phys_addr(unsigned int user_pid, unsigned long long user_addr){
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *pte;
    unsigned long phys_addr;
    struct mm_struct *mm;
    swp_entry_t swp_entry;
    
    mm = pid_task(find_vpid(pid), PIDTYPE_PID)->mm;

    pgd = pgd_offset(mm, addr); if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))  return 0;
    p4d = p4d_offset(pgd, addr); if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) return 0;
    pud = pud_offset(p4d, addr); if (pud_none(*pud) || unlikely(pud_bad(*pud))) return 0;
    pmd = pmd_offset(pud, addr); if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) return 0;

    pte = pte_offset_kernel(pmd, addr); 
    if (pte == NULL ) { pr_info("[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [N/A] swap identifier [N/A]\n",pid, addr);  return 0; }
    else if (pte_present(*pte) == 0) {
        swp_entry = __pte_to_swp_entry(*pte);
        pr_info("[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [N/A] swap identifier [%lx]\n", pid, addr,swp_entry.val);  return 0;
    }

    phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) | (addr & ~PAGE_MASK);
    pr_info("[CSE330-Memory-Manager] PID [%d]: virtual address [%llx] physical address [%lx] swap identifier [NA]\n", pid, addr, phys_addr);

    return 0;
}

static int __init memory_manager_init(void) {
    pr_info("[CSE330] Module init\n");
    struct task_struct *task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        pr_err("[CSE330-Memory-Manager] Invalid PID\n");
        return -EINVAL;
    } else if (!task->mm) {
        pr_err("[CSE330-Memory-Manager] Invalid address\n");
        return -EINVAL;
    }

    return find_phys_addr(pid, addr);
}

static void __exit memory_manager_exit(void) {
    pr_info("[CSE330] Module exit\n");
}

module_init(memory_manager_init);
module_exit(memory_manager_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bob");
MODULE_DESCRIPTION("memory_manager");