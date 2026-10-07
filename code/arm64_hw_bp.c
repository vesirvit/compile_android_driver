/*
 * 硬件断点正确绑定到线程(task_struct)而非进程ID
 * 适配Linux 5.10+内核 - 使用register_user_hw_breakpoint/unregister_hw_breakpoint
 */

#include "arm64_hw_bp.h"
#include "kallsyms_lookup_api.h"

// 断点数据结构
typedef struct _HW_BREAKPOINT_INFO {
    pid_t tid;
    pid_t tgid;
    uintptr_t addr;
    uint32_t type;
    bool active;
    struct perf_event *pe;
} HW_BREAKPOINT_INFO, *PHW_BREAKPOINT_INFO;

typedef struct _BREAKPOINT_OPERATION {
    pid_t tid;
    uintptr_t addr;
    uint32_t type;
} BREAKPOINT_OPERATION, *PBREAKPOINT_OPERATION;

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char __user *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

//由于断点回调里面禁用了浮点数类型，所以这边使用uint32_t代传参数
typedef struct _BULLET_ROT {
    uint32_t Pitch; //用户层实际传入浮点类型
    uint32_t Yaw;
    uint32_t Roll;
} BULLET_ROT, *PBULLET_ROT;

// IOCTL操作码
enum HW_BREAKPOINT_OPERATIONS {
    OP_READ_MEM = 0x601,
    OP_WRITE_MEM = 0x602,
    OP_MODULE_BASE = 0x603,
    OP_SET_BREAKPOINT = 0x604,
    OP_CLEAR_BREAKPOINT = 0x605,
    OP_LIST_BREAKPOINTS = 0x606,
    OP_CLEAR_ALL_BREAKPOINTS = 0x607,
    OP_SET_HOOK_PC = 0x608,
    OP_SET_BULLET_ROT = 0x609,
};

// 内部断点结构 - 简化版
struct hw_breakpoint_entry {
    HW_BREAKPOINT_INFO info;
    struct task_struct *task;
    struct list_head list;
    atomic_t state;        // 0=正常, 1=已移动
    uint64_t orig_addr;
    struct perf_event_attr orig_attr;
    spinlock_t lock;       // 保护状态
};

// 全局变量
static DEFINE_MUTEX(bp_mutex);
static LIST_HEAD(bp_list);
static int bp_count = 0;
static atomic64_t g_hook_pc;
static BULLET_ROT bullet_rot;
#define MAX_BREAKPOINTS 16

// 函数声明
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static void hw_breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs);
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, uint32_t type);
static int clear_hw_breakpoint(pid_t tid, uintptr_t addr);
static void clear_all_breakpoints(void);
static struct task_struct *get_thread_by_tid(pid_t tid);

// 根据内核版本选择合适的kmap函数
static void *safe_kmap(struct page *page)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    // Linux 5.11+ 使用 kmap_local_page
    return kmap_local_page(page);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
    // Linux 5.3 - 5.10 使用 kmap
    return kmap(page);
#else
    // 更早版本使用 kmap_atomic
    return kmap_atomic(page);
#endif
}

static void safe_kunmap(void *addr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    // Linux 5.11+ 使用 kunmap_local
    kunmap_local(addr);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
    // Linux 5.3 - 5.10 使用 kunmap
    kunmap(addr);
#else
    // 更早版本使用 kunmap_atomic
    kunmap_atomic(addr);
#endif
}

// 根据线程ID获取task_struct
static struct task_struct *get_thread_by_tid(pid_t tid)
{
    struct task_struct *task = NULL;
    struct pid *pid_struct = NULL;
    
    pid_struct = find_get_pid(tid);
    if (!pid_struct)
        return NULL;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    return task;
}

// 物理地址翻译函数
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    p4d_t *p4d;
    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    
    pud = pud_offset(p4d, va);
#else
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    pud = pud_offset(pgd, va);
#endif

    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}

// 检查物理地址范围
static inline bool is_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
    return (addr + size <= virt_to_phys(high_memory));
}

// 读取物理地址
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size)
{
    void *mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;
    
    if (!is_valid_phys_addr_range(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_to_user(buffer, mapped, size)) {
        iounmap(mapped);
        return false;
    }

    iounmap(mapped);
    return true;
}

// 写入物理地址
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size)
{
    void *mapped;

    if (!pfn_valid(__phys_to_pfn(pa)))
        return false;
    
    if (!is_valid_phys_addr_range(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_from_user(mapped, buffer, size)) {
        iounmap(mapped);
        return false;
    }

    iounmap(mapped);
    return true;
}

// 读取进程内存
static bool read_process_memory(pid_t pid, uintptr_t addr, 
                               void __user *buffer, size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    phys_addr_t pa;
    bool result = false;
    struct vm_area_struct *vma;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return false;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
    pa = translate_linear_address(mm, addr);
    
    if (pa) {
        result = read_physical_address(pa, buffer, size);
    } else {
        vma = find_vma(mm, addr);
        if (vma) {
            if (clear_user(buffer, size) == 0) {
                result = true;
            }
        }
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return result;
}

// 写入进程内存
static bool write_process_memory(pid_t pid, uintptr_t addr, 
                                const void __user *buffer, size_t size)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    phys_addr_t pa;
    bool result = false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return false;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
    pa = translate_linear_address(mm, addr);
    
    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return result;
}

// 获取模块基址
#define ARC_PATH_MAX 256
static uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    struct vm_area_struct *vma = NULL;
    uintptr_t base_addr = 0;
    int path_len;
    char buf[ARC_PATH_MAX];
    char *path_nm;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        return 0;
    }

    mm = get_task_mm(task);
    put_pid(pid_struct);
    
    if (!mm) {
        put_task_struct(task);
        return 0;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        if (!vma->vm_file)
            continue;

        path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
        if (IS_ERR(path_nm))
            continue;

        path_len = strlen(path_nm);
        if (path_len <= 0)
            continue;

        if (strstr(path_nm, name) != NULL) {
            base_addr = vma->vm_start;
            break;
        }
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
    
    mmput(mm);
    put_task_struct(task);
    return base_addr;
}

/**
 * process_rw_mem - 兼容Linux 4.9 ~ 6.12内核版本的进程内存读写
 */
static int process_rw_mem(struct task_struct *task, unsigned long addr,
                          void *buf, size_t len, int write)
{
    struct mm_struct *mm;
    struct page *page = NULL;
    void *kaddr;
    size_t total = 0;
    size_t chunk;
    unsigned long offset;
    int ret;
    int gup_flags = write ? FOLL_WRITE : 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    int locked = 1;  // 用于6.5+内核的locked参数
#endif

    if (!task || !task->mm || !buf || !len)
        return -EINVAL;

    mm = task->mm;
    
    // 兼容不同内核版本的mmap锁
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif

    while (len > 0) {
        offset = offset_in_page(addr);
        chunk = min(len, PAGE_SIZE - offset);

        // 根据内核版本选择正确的get_user_pages_remote调用
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        // Linux 6.5 - 6.12: get_user_pages_remote(mm, start, nr_pages, gup_flags, pages, locked)
        ret = get_user_pages_remote(mm, addr, 1, gup_flags, &page, &locked);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
        // Linux 5.9 - 6.4: get_user_pages_remote(mm, start, nr_pages, gup_flags, pages, vmas, NULL)
        ret = get_user_pages_remote(mm, addr, 1, gup_flags, &page, NULL, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
        // Linux 4.10 - 5.8: get_user_pages_remote(tsk, mm, start, nr_pages, gup_flags, pages, vmas)
        ret = get_user_pages_remote(task, mm, addr, 1, gup_flags, &page, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
        // Linux 4.9: get_user_pages_remote(tsk, mm, start, nr_pages, write, force, pages, vmas)
        ret = get_user_pages_remote(task, mm, addr, 1, write, 0, &page, NULL);
#else
        ret = -EINVAL;
#endif

        if (ret < 0)
            goto out;

        // 使用兼容的kmap函数
        kaddr = safe_kmap(page);
        if (!kaddr) {
            put_page(page);
            ret = -ENOMEM;
            goto out;
        }
        
        if (write) {
            memcpy(kaddr + offset, buf, chunk);
            flush_dcache_page(page);
        } else {
            memcpy(buf, kaddr + offset, chunk);
        }
        
        safe_kunmap(kaddr);
        put_page(page);

        buf += chunk;
        addr += chunk;
        len -= chunk;
        total += chunk;
    }

out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif

    return total ? total : ret;
}

/**
 * process_read_mem - 读取进程内存
 */
ssize_t process_read_mem(struct task_struct *task, unsigned long addr,
                         void *buf, size_t len)
{
    return process_rw_mem(task, addr, buf, len, 0);
}

/**
 * process_write_mem - 写入进程内存
 */
ssize_t process_write_mem(struct task_struct *task, unsigned long addr,
                          const void *buf, size_t len)
{
    return process_rw_mem(task, addr, (void *)buf, len, 1);
}

// 断点移动函数
static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_addr)
{
    struct perf_event_attr tmp_attr;
    
    if (!bp || !next_addr)
        return false;
    
    tmp_attr = bp->attr;
    tmp_attr.bp_addr = next_addr;
    tmp_attr.bp_len = HW_BREAKPOINT_LEN_4;
    tmp_attr.bp_type = HW_BREAKPOINT_X;
    tmp_attr.disabled = 0;
    
    return (modify_user_hw_breakpoint_sym(bp, &tmp_attr) == 0);
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, struct perf_event_attr *orig_attr)
{
    if (!bp || !orig_attr)
        return false;
    
    orig_attr->disabled = 0;
    return (modify_user_hw_breakpoint_sym(bp, orig_attr) == 0);
}

// 断点回调函数 - 修复版
static void hw_breakpoint_handler(struct perf_event *bp,
                                 struct perf_sample_data *data,
                                 struct pt_regs *regs)
{
    struct hw_breakpoint_entry *entry = bp->overflow_handler_context;
    struct task_struct *task = current;
    unsigned long flags;
    int old_state;
    uint64_t hook_pc;
    
    if (!entry)
        return;
    
    // 检查是否是目标线程
    if (task->pid != entry->info.tid)
        return;
    
    // 先获取当前状态
    old_state = atomic_read(&entry->state);
    
    // 检查是否需要修改PC
    hook_pc = atomic64_read(&g_hook_pc);
    if (hook_pc != 0) {
        regs->pc = hook_pc;
        printk(KERN_DEBUG "BP hook PC to 0x%llx\n", hook_pc);
    }
    
    // 如果是第一次命中且子弹旋转数据有效，写入内存
    if (old_state == 0) {
        if (bullet_rot.Pitch != 0 || bullet_rot.Yaw != 0 || bullet_rot.Roll != 0) {
            process_write_mem(task, regs->regs[2], &bullet_rot, sizeof(bullet_rot));
            printk(KERN_DEBUG "BP write bullet_rot to regs[2]=0x%lx\n", 
                   (unsigned long)regs->regs[2]);
        }
    }
    
    // 断点移动状态机
    spin_lock_irqsave(&entry->lock, flags);
    old_state = atomic_read(&entry->state);
    
    if (old_state == 0) {
        // 第一次命中：保存原始信息，移动到下一条指令
        entry->orig_addr = entry->info.addr;
        entry->orig_attr = bp->attr;
        
        if (arm64_move_bp_to_next_instruction(bp, regs->pc + 4)) {
            atomic_set(&entry->state, 1);
            printk(KERN_DEBUG "BP moved from 0x%lx to 0x%llx\n", 
                   (unsigned long)entry->info.addr, regs->pc + 4);
        }
    } else if (old_state == 1) {
        // 第二次命中：恢复原始断点
        if (arm64_recovery_bp_to_original(bp, &entry->orig_attr)) {
            atomic_set(&entry->state, 0);
            printk(KERN_DEBUG "BP restored to 0x%lx\n", (unsigned long)entry->orig_addr);
        }
    }
    
    spin_unlock_irqrestore(&entry->lock, flags);
}

// 设置硬件断点
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, uint32_t type)
{
    struct task_struct *task = NULL;
    struct perf_event_attr attr;
    struct hw_breakpoint_entry *entry;
    struct hw_breakpoint_entry *tmp;
    int bp_len;
    int ret = 0;
    
    // 检查断点数量限制
    mutex_lock(&bp_mutex);
    if (bp_count >= MAX_BREAKPOINTS) {
        mutex_unlock(&bp_mutex);
        return -ENOSPC;
    }
    mutex_unlock(&bp_mutex);
    
    // 根据线程ID获取task_struct
    task = get_thread_by_tid(tid);
    if (!task) {
        return -ESRCH;
    }
    
    mutex_lock(&bp_mutex);
    
    // 检查是否已存在断点
    list_for_each_entry(tmp, &bp_list, list) {
        if (tmp->info.tid == tid && tmp->info.addr == addr) {
            ret = -EEXIST;
            goto out_unlock;
        }
    }
    
    // 分配断点条目
    entry = kzalloc(sizeof(struct hw_breakpoint_entry), GFP_KERNEL);
    if (!entry) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    
    // 初始化
    atomic_set(&entry->state, 0);
    spin_lock_init(&entry->lock);
    entry->orig_addr = 0;
    memset(&entry->orig_attr, 0, sizeof(entry->orig_attr));
    
    // 设置perf事件属性
    memset(&attr, 0, sizeof(struct perf_event_attr));
    ptrace_breakpoint_init(&attr);
    
    // 设置断点类型和大小
    switch (type) {
        case BP_TYPE_INST:
            attr.bp_type = HW_BREAKPOINT_X;
            bp_len = HW_BREAKPOINT_LEN_4;
            break;
        case BP_TYPE_READ:
            attr.bp_type = HW_BREAKPOINT_R;
            bp_len = HW_BREAKPOINT_LEN_8;
            break;
        case BP_TYPE_WRITE:
            attr.bp_type = HW_BREAKPOINT_W;
            bp_len = HW_BREAKPOINT_LEN_8;
            break;
        case BP_TYPE_RW:
            attr.bp_type = HW_BREAKPOINT_RW;
            bp_len = HW_BREAKPOINT_LEN_8;
            break;
        default:
            kfree(entry);
            ret = -EINVAL;
            goto out_unlock;
    }
    
    attr.bp_addr = addr;
    attr.bp_len = bp_len;
    attr.disabled = 0;

    // 创建断点
    entry->info.pe = register_user_hw_breakpoint_sym(&attr, hw_breakpoint_handler, entry, task);
    
    if (IS_ERR(entry->info.pe)) {
        ret = PTR_ERR(entry->info.pe);
        kfree(entry);
        goto out_unlock;
    }
    
    // 初始化断点信息
    entry->info.tid = tid;
    entry->info.tgid = task->tgid;
    entry->info.addr = addr;
    entry->info.type = type;
    entry->info.active = true;
    entry->task = task;
    get_task_struct(task);
    INIT_LIST_HEAD(&entry->list);
    
    // 添加到链表
    list_add_tail(&entry->list, &bp_list);
    bp_count++;

    ret = 0;
    printk(KERN_INFO "BP set for thread %d at 0x%lx\n", tid, (unsigned long)addr);
    
out_unlock:
    mutex_unlock(&bp_mutex);
    return ret;
}

// 清除硬件断点
static int clear_hw_breakpoint(pid_t tid, uintptr_t addr)
{
    struct hw_breakpoint_entry *entry, *tmp;
    int ret = -ENOENT;
    
    mutex_lock(&bp_mutex);
    
    list_for_each_entry_safe(entry, tmp, &bp_list, list) {
        if (entry->info.tid == tid && entry->info.addr == addr) {
            if (entry->info.pe) {
                unregister_hw_breakpoint_sym(entry->info.pe);
                entry->info.pe = NULL;
            }
            
            if (entry->task) {
                put_task_struct(entry->task);
                entry->task = NULL;
            }
            
            list_del(&entry->list);
            kfree(entry);
            bp_count--;
            
            ret = 0;
            printk(KERN_INFO "BP cleared for thread %d at 0x%lx\n", tid, (unsigned long)addr);
            break;
        }
    }
    
    mutex_unlock(&bp_mutex);
    return ret;
}

// 清除所有断点
static void clear_all_breakpoints(void)
{
    struct hw_breakpoint_entry *entry, *tmp;
    
    mutex_lock(&bp_mutex);
    
    list_for_each_entry_safe(entry, tmp, &bp_list, list) {
        if (entry->info.pe) {
            unregister_hw_breakpoint_sym(entry->info.pe);
            entry->info.pe = NULL;
        }
        
        if (entry->task) {
            put_task_struct(entry->task);
            entry->task = NULL;
        }
        
        list_del(&entry->list);
        kfree(entry);
    }
    
    bp_count = 0;
    mutex_unlock(&bp_mutex);
    
    printk(KERN_INFO "All breakpoints cleared\n");
}

// IOCTL分发函数
static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = 0;

    switch (cmd) {
    case OP_READ_MEM: {
        COPY_MEMORY cm;
        
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        
        break;
    }

    case OP_WRITE_MEM: {
        COPY_MEMORY cm;
        
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        
        break;
    }

    case OP_MODULE_BASE: {
        MODULE_BASE mb;
        char module_name[256];
        
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        
        if (!mb.name)
            return -EFAULT;
        
        if (copy_from_user(module_name, mb.name, sizeof(module_name) - 1))
            return -EFAULT;
        module_name[sizeof(module_name) - 1] = '\0';
        
        mb.base = get_module_base(mb.pid, module_name);
        
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        
        break;
    }

    case OP_SET_BREAKPOINT: {
        BREAKPOINT_OPERATION bp_op;
        
        if (copy_from_user(&bp_op, (void __user *)arg, sizeof(bp_op)))
            return -EFAULT;
        
        ret = set_hw_breakpoint(bp_op.tid, bp_op.addr, bp_op.type);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_CLEAR_BREAKPOINT: {
        BREAKPOINT_OPERATION bp_op;
        
        if (copy_from_user(&bp_op, (void __user *)arg, sizeof(bp_op)))
            return -EFAULT;
        
        ret = clear_hw_breakpoint(bp_op.tid, bp_op.addr);
        if (ret < 0)
            return ret;
        
        break;
    }

    case OP_LIST_BREAKPOINTS: {
        struct hw_breakpoint_entry *entry;
        HW_BREAKPOINT_INFO info;
        int idx = 0;
        
        mutex_lock(&bp_mutex);
        
        list_for_each_entry(entry, &bp_list, list) {
            memset(&info, 0, sizeof(info));
            info.tid = entry->info.tid;
            info.tgid = entry->info.tgid;
            info.addr = entry->info.addr;
            info.type = entry->info.type;
            info.active = entry->info.active;
            
            if (copy_to_user((void __user *)(arg + idx * sizeof(info)), 
                            &info, sizeof(info))) {
                mutex_unlock(&bp_mutex);
                return -EFAULT;
            }
            idx++;
        }
        
        mutex_unlock(&bp_mutex);
        break;
    }

    case OP_CLEAR_ALL_BREAKPOINTS:
        clear_all_breakpoints();
        break;
    
    case OP_SET_HOOK_PC: {
        uint64_t hook_pc;
        
        if (copy_from_user(&hook_pc, (void __user *)arg, sizeof(hook_pc)))
            return -EFAULT;
        
        atomic64_set(&g_hook_pc, hook_pc);
        printk(KERN_INFO "Hook PC set to 0x%llx\n", hook_pc);
        break;
    }
    
    case OP_SET_BULLET_ROT: {
        BULLET_ROT rot;
        
        if (copy_from_user(&rot, (void __user *)arg, sizeof(rot)))
            return -EFAULT;
        
        memcpy(&bullet_rot, &rot, sizeof(struct _BULLET_ROT));
        printk(KERN_INFO "Bullet rot set: Pitch=%u, Yaw=%u, Roll=%u\n", 
               rot.Pitch, rot.Yaw, rot.Roll);
        break;
    }
    
    default:
        return -ENOTTY;
    }

    return ret;
}

// 文件操作结构
static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl = dispatch_ioctl,
};

// misc设备定义
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_fops,
    .mode = 0660,
};

// 模块初始化
static int __init driver_entry(void)
{
    int ret;
    
    if (!init_kallsyms_lookup()) {
        printk(KERN_ERR "Failed to Get Breakpoint Functions!!!");
        return EBADF;
    }
    
    INIT_LIST_HEAD(&bp_list);
    atomic64_set(&g_hook_pc, 0);
    memset(&bullet_rot, 0, sizeof(bullet_rot));
    
    ret = misc_register(&misc_dev);
    if (ret) {
        printk(KERN_ERR "Failed to register misc device\n");
        return ret;
    }
    
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module loaded\n");
    return 0;
}

// 模块卸载
static void __exit driver_unload(void)
{
    clear_all_breakpoints();
    misc_deregister(&misc_dev);
    printk(KERN_INFO "ARM64 Hardware Breakpoint Module unloaded\n");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("ARM64 Hardware Breakpoint Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("陈依涵");
MODULE_VERSION("5.1");