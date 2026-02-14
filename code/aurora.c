#include "aurora.h"
#include <linux/random.h>

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

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_SET_HW_BREAKPOINT = 0x804,   // 设置硬件断点 (参数为线程TID)
    OP_REMOVE_HW_BREAKPOINT = 0x805, // 移除硬件断点
    OP_SET_HOOK_PC = 0x806,          // 设置Hook PC值
    OP_GET_HOOK_PC = 0x807,          // 获取当前Hook PC值
};

// 可选的设备名池
static const char* device_name_pool[] = {
    "SynapseKernel",
    "AetherBridge",
    "NexusGuard",
    "QuantumLink",
    "VortexCore",
    "PhantomNode",
    "TitanShield",
    "OrionDriver",
    "ZenithPath",
    "CelestialGate",
    "NebulaCore",
    "StellarLink",
    "InfinityHook",
    "EchoSys",
    "ChronoFrame",
    "PulseEngine",
    "ApexBridge",
    "NovaNode",
    "SolarFlare",
    "CosmicPath"
};

#define DEVICE_POOL_SIZE (sizeof(device_name_pool) / sizeof(device_name_pool[0]))
static char selected_device_name[64];
static struct miscdevice misc_dev;

// 全局Hook PC值
atomic64_t g_hook_pc = ATOMIC64_INIT(0);

// 硬件断点相关结构
typedef struct {
    struct perf_event *event;
    pid_t tid;                      // 线程ID
    pid_t tgid;                      // 线程组ID (进程ID)
    uintptr_t addr;
    int type;
    int len;
    bool active;
} hw_breakpoint_entry;

#define MAX_HW_BREAKPOINTS 4
static hw_breakpoint_entry hw_breakpoints[MAX_HW_BREAKPOINTS];
static DEFINE_MUTEX(hw_bp_mutex);

// 函数前向声明
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, int type, int len);
static int remove_hw_breakpoint(pid_t tid, uintptr_t addr);
static void set_hook_pc(uint64_t pc);
static uint64_t get_hook_pc(void);

// 从池中随机选择一个设备名
static void select_random_device_name(void)
{
    unsigned int rand_val;
    int index;
    
    get_random_bytes(&rand_val, sizeof(rand_val));
    index = rand_val % DEVICE_POOL_SIZE;
    
    snprintf(selected_device_name, sizeof(selected_device_name), 
             "%s", device_name_pool[index]);
    
    printk(KERN_INFO "Aurora: Selected random device name: %s\n", selected_device_name);
}

// 设置Hook PC值
static void set_hook_pc(uint64_t pc)
{
    atomic64_set(&g_hook_pc, pc);
    printk(KERN_INFO "Aurora: Hook PC set to 0x%llx\n", (unsigned long long)pc);
}

// 获取Hook PC值
static uint64_t get_hook_pc(void)
{
    return (uint64_t)atomic64_read(&g_hook_pc);
}

// 硬件断点回调函数 - 在线程上下文中执行
static void hw_breakpoint_handler(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs)
{
    hw_breakpoint_entry *entry = event->overflow_handler_context;
    uint64_t hook_pc;
    struct task_struct *current_task = current;
    
    if (!entry || !entry->active)
        return;
    
    // 验证是否是目标线程触发的断点
    if (current_task->pid != entry->tid) {
        // 如果不是目标线程，忽略（理论上不会发生，因为断点是线程特定的）
        return;
    }
    
    printk(KERN_INFO "Aurora: Hardware breakpoint hit on thread TID=%d (process PID=%d) at 0x%llx\n", 
           entry->tid, entry->tgid, (unsigned long long)entry->addr);
    
    // 读取全局Hook PC值
    hook_pc = get_hook_pc();
    
    if (hook_pc != 0) {
        unsigned long old_ip = instruction_pointer(regs);
        printk(KERN_INFO "Aurora: Thread TID=%d: Modifying PC from 0x%lx to 0x%llx\n",
               entry->tid, old_ip, (unsigned long long)hook_pc);
        
        // 修改指令指针寄存器
        instruction_pointer_set(regs, hook_pc);
    }
    
    // 注意：不断开断点，让断点保持活动状态
    // 如果希望断点只触发一次，可以在这里调用 perf_event_disable(entry->event);
}

// 设置硬件断点 - 绑定到特定线程
static int set_hw_breakpoint(pid_t tid, uintptr_t addr, int type, int len)
{
    struct task_struct *task;
    struct pid *pid_struct;
    struct perf_event_attr attr;
    hw_breakpoint_entry *entry = NULL;
    int i, ret = 0;
    
    // 参数验证
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        printk(KERN_ERR "Aurora: Invalid breakpoint length %d\n", len);
        return -EINVAL;
    }
    
    if (type != HW_BREAKPOINT_X && type != HW_BREAKPOINT_R && 
        type != HW_BREAKPOINT_W && type != (HW_BREAKPOINT_R | HW_BREAKPOINT_W)) {
        printk(KERN_ERR "Aurora: Invalid breakpoint type %d\n", type);
        return -EINVAL;
    }
    
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.bp_addr = addr;
    attr.bp_len = len;
    attr.bp_type = type;
    attr.disabled = 1;
    attr.inherit = 0;           // 不继承到子线程
    attr.pinned = 1;
    attr.exclude_kernel = 1;    // 排除内核空间
    attr.exclude_user = 0;       // 监控用户空间
    attr.exclude_hv = 1;         // 排除Hypervisor
    attr.exclude_host = 1;       // 对于KVM
    
    // 查找空闲断点槽位
    mutex_lock(&hw_bp_mutex);
    for (i = 0; i < MAX_HW_BREAKPOINTS; i++) {
        if (!hw_breakpoints[i].active) {
            entry = &hw_breakpoints[i];
            break;
        }
    }
    
    if (!entry) {
        mutex_unlock(&hw_bp_mutex);
        printk(KERN_ERR "Aurora: No free hardware breakpoint slots\n");
        return -EBUSY;
    }
    
    // 获取目标线程（使用TID）
    pid_struct = find_get_pid(tid);
    if (!pid_struct) {
        mutex_unlock(&hw_bp_mutex);
        printk(KERN_ERR "Aurora: Thread TID=%d not found\n", tid);
        return -ESRCH;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_struct);
        mutex_unlock(&hw_bp_mutex);
        printk(KERN_ERR "Aurora: Cannot get task for TID=%d\n", tid);
        return -ESRCH;
    }
    
    // 记录线程信息
    entry->tid = tid;
    entry->tgid = task->tgid;
    
    printk(KERN_INFO "Aurora: Setting hardware breakpoint on thread TID=%d (process PID=%d) at 0x%llx\n",
           tid, task->tgid, (unsigned long long)addr);
    
    // 创建perf事件，绑定到特定线程
    // 注意：第三个参数传递-1表示绑定到指定CPU，传递NULL表示绑定到当前线程
    // 这里传递tid，perf_event_create_kernel_counter会自动绑定到该线程
    entry->event = perf_event_create_kernel_counter(&attr, tid, NULL, 
                                                     hw_breakpoint_handler, entry);
    
    if (IS_ERR(entry->event)) {
        ret = PTR_ERR(entry->event);
        entry->event = NULL;
        put_task_struct(task);
        put_pid(pid_struct);
        mutex_unlock(&hw_bp_mutex);
        printk(KERN_ERR "Aurora: Failed to create perf event for TID=%d: %d\n", tid, ret);
        return ret;
    }
    
    entry->addr = addr;
    entry->type = type;
    entry->len = len;
    entry->active = true;
    
    // 启用断点
    perf_event_enable(entry->event);
    
    put_task_struct(task);
    put_pid(pid_struct);
    mutex_unlock(&hw_bp_mutex);
    
    printk(KERN_INFO "Aurora: Hardware breakpoint successfully set on thread TID=%d\n", tid);
    
    return 0;
}

// 移除硬件断点
static int remove_hw_breakpoint(pid_t tid, uintptr_t addr)
{
    int i;
    
    mutex_lock(&hw_bp_mutex);
    for (i = 0; i < MAX_HW_BREAKPOINTS; i++) {
        if (hw_breakpoints[i].active && 
            hw_breakpoints[i].tid == tid && 
            hw_breakpoints[i].addr == addr) {
            
            if (hw_breakpoints[i].event) {
                perf_event_disable(hw_breakpoints[i].event);
                perf_event_release_kernel(hw_breakpoints[i].event);
                hw_breakpoints[i].event = NULL;
            }
            
            printk(KERN_INFO "Aurora: Hardware breakpoint removed for thread TID=%d at 0x%llx\n", 
                   tid, (unsigned long long)addr);
            
            hw_breakpoints[i].active = false;
            hw_breakpoints[i].tid = 0;
            hw_breakpoints[i].tgid = 0;
            hw_breakpoints[i].addr = 0;
            hw_breakpoints[i].type = 0;
            hw_breakpoints[i].len = 0;
            
            mutex_unlock(&hw_bp_mutex);
            return 0;
        }
    }
    mutex_unlock(&hw_bp_mutex);
    
    printk(KERN_ERR "Aurora: No breakpoint found for thread TID=%d at 0x%llx\n", 
           tid, (unsigned long long)addr);
    return -ENOENT;
}

// 模块卸载时清理所有断点
static void cleanup_all_breakpoints(void)
{
    int i;
    
    mutex_lock(&hw_bp_mutex);
    for (i = 0; i < MAX_HW_BREAKPOINTS; i++) {
        if (hw_breakpoints[i].active && hw_breakpoints[i].event) {
            perf_event_disable(hw_breakpoints[i].event);
            perf_event_release_kernel(hw_breakpoints[i].event);
            hw_breakpoints[i].event = NULL;
        }
        hw_breakpoints[i].active = false;
        hw_breakpoints[i].tid = 0;
        hw_breakpoints[i].tgid = 0;
        hw_breakpoints[i].addr = 0;
    }
    mutex_unlock(&hw_bp_mutex);
}

static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
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

static inline bool is_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
    return (addr + size <= virt_to_phys(high_memory));
}

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

static bool read_process_memory(pid_t pid, uintptr_t addr, 
                               void __user *buffer, size_t size)
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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = read_physical_address(pa, buffer, size);
    } else {
        struct vm_area_struct *vma = find_vma(mm, addr);
        if (vma) {
            if (clear_user(buffer, size) == 0) {
                result = true;
            }
        }
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

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

    pa = translate_linear_address(mm, addr);
    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

#define ARC_PATH_MAX 256

static uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    struct vm_area_struct *vma = NULL;
    uintptr_t base_addr = 0;
    int path_len;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        char buf[ARC_PATH_MAX];
        char *path_nm;

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

    mmput(mm);
    put_task_struct(task);
    return base_addr;
}

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
    static char key[256] = {0};
    static bool is_verified = false;

    switch (cmd) {
    case OP_INIT_KEY:
        if (!is_verified) {
            if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) == 0) {
                key[sizeof(key) - 1] = '\0';
                is_verified = true;
            } else {
                return -EFAULT;
            }
        }
        break;

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

    // 设置硬件断点 - 参数为线程TID
    case OP_SET_HW_BREAKPOINT: {
        struct {
            pid_t tid;          // 线程ID
            uintptr_t addr;      // 断点地址
            int type;            // 断点类型
            int len;             // 断点长度
        } bp_config;
        
        if (!is_verified)
            return -EACCES;
        
        if (copy_from_user(&bp_config, (void __user *)arg, sizeof(bp_config)))
            return -EFAULT;
        
        return set_hw_breakpoint(bp_config.tid, bp_config.addr, 
                                 bp_config.type, bp_config.len);
    }

    // 移除硬件断点 - 参数为线程TID和地址
    case OP_REMOVE_HW_BREAKPOINT: {
        struct {
            pid_t tid;          // 线程ID
            uintptr_t addr;      // 断点地址
        } bp_remove;
        
        if (!is_verified)
            return -EACCES;
        
        if (copy_from_user(&bp_remove, (void __user *)arg, sizeof(bp_remove)))
            return -EFAULT;
        
        return remove_hw_breakpoint(bp_remove.tid, bp_remove.addr);
    }

    // 设置Hook PC值
    case OP_SET_HOOK_PC: {
        uint64_t pc_value;
        
        if (!is_verified)
            return -EACCES;
        
        if (copy_from_user(&pc_value, (void __user *)arg, sizeof(pc_value)))
            return -EFAULT;
        
        set_hook_pc(pc_value);
        break;
    }

    // 获取当前Hook PC值
    case OP_GET_HOOK_PC: {
        uint64_t pc_value = get_hook_pc();
        
        if (!is_verified)
            return -EACCES;
        
        if (copy_to_user((void __user *)arg, &pc_value, sizeof(pc_value)))
            return -EFAULT;
        
        break;
    }

    default:
        return -ENOTTY;
    }

    return 0;
}

static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void)
{
    int ret;
    int i;
    
    select_random_device_name();
    
    // 初始化硬件断点数组
    for (i = 0; i < MAX_HW_BREAKPOINTS; i++) {
        hw_breakpoints[i].event = NULL;
        hw_breakpoints[i].active = false;
        hw_breakpoints[i].tid = 0;
        hw_breakpoints[i].tgid = 0;
        hw_breakpoints[i].addr = 0;
        hw_breakpoints[i].type = 0;
        hw_breakpoints[i].len = 0;
    }
    
    // 初始化Hook PC值
    atomic64_set(&g_hook_pc, 0);
    
    // 注册设备
    misc_dev.minor = MISC_DYNAMIC_MINOR;
    misc_dev.name = selected_device_name;
    misc_dev.fops = &dispatch_fops;
    misc_dev.mode = 0666;
    
    ret = misc_register(&misc_dev);
    if (ret) {
        printk(KERN_ERR "Aurora: Failed to register device %s, error %d\n", 
               selected_device_name, ret);
        return ret;
    }
    
    printk(KERN_INFO "Aurora: Successfully registered random device: %s\n", 
           selected_device_name);
    printk(KERN_INFO "Aurora: Hardware breakpoint support enabled (max %d breakpoints, thread-specific)\n", 
           MAX_HW_BREAKPOINTS);
    return 0;
}

static void __exit driver_unload(void)
{
    // 清理所有硬件断点
    cleanup_all_breakpoints();
    
    // 注销设备
    misc_deregister(&misc_dev);
    
    printk(KERN_INFO "Aurora: Unregistered device: %s\n", selected_device_name);
    printk(KERN_INFO "Aurora: Hardware breakpoints cleaned up\n");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module with Thread-Specific Hardware Breakpoint Support");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("2.2");