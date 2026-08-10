#include "aurora.h"
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/mutex.h>

// 触摸事件结构体
struct touch_event {
    int x;          // 屏幕像素坐标 X (0 ~ 屏幕宽-1)
    int y;          // 屏幕像素坐标 Y (0 ~ 屏幕高-1)
    int pressure;   // 压力值 (0-255)
};

// 屏幕分辨率结构体（用户态通过 OP_TOUCH_SET_RESOLUTION 传入）
struct screen_resolution {
    int width;      // 屏幕像素宽（必须 > 0）
    int height;     // 屏幕像素高（必须 > 0）
};

// 设备结构体
struct vtouch_dev {
    struct input_dev *input;
    int touch_active;
};

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
    OP_INIT_KEY = 600,
    OP_READ_MEM = 601,
    OP_WRITE_MEM = 602,
    OP_MODULE_BASE = 603,
    OP_TOUCH_PRESS = 604,
    OP_TOUCH_RELEASE = 605,
    OP_TOUCH_MOVE = 606,
    OP_TOUCH_SET_RESOLUTION = 607
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
static char selected_device_name[64];  // 存储实际使用的设备名
static struct miscdevice misc_dev;

static struct vtouch_dev vtouch_device;

// 保护虚拟 input 设备的创建/注销（ensure 与 set_resolution 并发时避免重复注册）
static DEFINE_MUTEX(vtouch_lock);

// 屏幕分辨率（屏幕像素）。默认 0 = 未设置，虚拟设备 abs 范围用 0-1023 兜底；
// 用户态通过 OP_TOUCH_SET_RESOLUTION 传入后，abs 范围 = 屏幕分辨率，实现点对点。
static int screen_width;
static int screen_height;


static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static int vtouch_ensure_input(struct vtouch_dev *dev);
static int vtouch_set_resolution(struct vtouch_dev *dev, int width, int height);

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

// 发送触摸事件（Type B 协议，正确的事件顺序）
// 坐标是屏幕像素坐标，虚拟设备 abs 范围已按屏幕分辨率设置，InputReader 1:1 映射到屏幕
// 注意：pressure 为 0 时部分 ROM 的 InputReader 会忽略触点，按下时强制最小压力 1
static void send_touch_event(struct vtouch_dev *dev, int x, int y, int pressure, int active)
{
    if (!dev->input)
        return;

    if (active && pressure < 1)
        pressure = 1;

    // 1. 选择触摸槽位
    input_mt_slot(dev->input, 0);

    // 2. 上报槽位状态（按下时内核自动分配 TRACKING_ID，抬起时自动发送 -1）
    input_mt_report_slot_state(dev->input, MT_TOOL_FINGER, active);

    if (active) {
        // 3. 上报坐标和压力
        input_report_abs(dev->input, ABS_MT_POSITION_X, x);
        input_report_abs(dev->input, ABS_MT_POSITION_Y, y);
        input_report_abs(dev->input, ABS_MT_PRESSURE, pressure);
    }

    // 4. 上报按键状态（用户态程序依赖 BTN_TOUCH 判断触摸有无）
    input_report_key(dev->input, BTN_TOUCH, active);
    input_report_key(dev->input, BTN_TOOL_FINGER, active);

    // 5. 同步事件
    input_sync(dev->input);

    // 保存当前状态
    dev->touch_active = active;
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
    (void)node;
    file->private_data = &vtouch_device;

    pr_info("vtouch: device opened\n");
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    struct vtouch_dev *dev = file->private_data;
    (void)node;

    // 如果触摸还处于激活状态，自动释放（release 事件不需要坐标）
    if (dev->touch_active) {
        pr_info("vtouch: auto-releasing touch on close\n");
        send_touch_event(dev, 0, 0, 0, 0);
    }

    pr_info("vtouch: device closed\n");

    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    static char key[256] = {0};
    static bool is_verified = false;
    
    struct vtouch_dev *dev = file->private_data;
    struct touch_event tev;
    int ret;

    switch (cmd) {
        case OP_INIT_KEY: {
            if (!is_verified) {
                if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) == 0) {
                    key[sizeof(key) - 1] = '\0';
                    is_verified = true;
                } else {
                    return -EFAULT;
                }
            }
            break;
        }

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

        case OP_TOUCH_SET_RESOLUTION: {
            struct screen_resolution sr;

            if (copy_from_user(&sr, (void __user *)arg, sizeof(sr)))
                return -EFAULT;

            pr_info("vtouch: ioctl SET_RESOLUTION %dx%d\n", sr.width, sr.height);
            ret = vtouch_set_resolution(dev, sr.width, sr.height);
            if (ret)
                return ret;
            break;
        }

        case OP_TOUCH_PRESS: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            ret = vtouch_ensure_input(dev);
            if (ret)
                return ret;

            pr_info("vtouch: ioctl PRESS x=%d y=%d pressure=%d (screen %dx%d)\n",
                    tev.x, tev.y, tev.pressure, screen_width, screen_height);
            send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
            break;
        }

        case OP_TOUCH_RELEASE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            ret = vtouch_ensure_input(dev);
            if (ret)
                return ret;

            pr_info("vtouch: ioctl RELEASE x=%d y=%d (screen %dx%d)\n",
                    tev.x, tev.y, screen_width, screen_height);
            send_touch_event(dev, tev.x, tev.y, 0, 0);
            break;
        }

        case OP_TOUCH_MOVE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            ret = vtouch_ensure_input(dev);
            if (ret)
                return ret;

            if (!dev->touch_active) {
                pr_warn("vtouch: ioctl MOVE called but touch is not active\n");
                return -EINVAL;
            }
            pr_info("vtouch: ioctl MOVE x=%d y=%d pressure=%d (screen %dx%d)\n",
                    tev.x, tev.y, tev.pressure, screen_width, screen_height);
            send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
            break;
        }

        default: {
            return -ENOTTY;
        }
    }

    return 0;
}

// 初始化输入设备（延迟注册：由 vtouch_ensure_input 在首次触摸前调用）
// abs 范围 = 屏幕分辨率（用户态传入），未设置时用 0-1023 兜底
static int vtouch_input_init(struct vtouch_dev *dev)
{
    struct input_dev *input;
    int ret;
    int abs_x_max;
    int abs_y_max;

    // 分配输入设备
    input = input_allocate_device();
    if (!input) {
        pr_err("vtouch: failed to allocate input device\n");
        return -ENOMEM;
    }

    // 设置设备名称
    input->name = "Virtual Touchscreen";
    input->id.bustype = BUS_VIRTUAL;
    input->id.vendor = 0x1234;
    input->id.product = 0x5678;
    input->id.version = 0x0001;

    // 设置事件类型
    __set_bit(EV_ABS, input->evbit);
    __set_bit(EV_SYN, input->evbit);
    __set_bit(EV_KEY, input->evbit);

    // 设置触摸按键
    __set_bit(BTN_TOUCH, input->keybit);
    __set_bit(BTN_TOOL_FINGER, input->keybit);

    // 绝对坐标范围 = 屏幕分辨率（点对点）：App 传屏幕像素坐标，1:1 映射
    abs_x_max = screen_width > 0 ? screen_width - 1 : 1023;
    abs_y_max = screen_height > 0 ? screen_height - 1 : 1023;
    input_set_abs_params(input, ABS_MT_POSITION_X, 0, abs_x_max, 0, 0);
    input_set_abs_params(input, ABS_MT_POSITION_Y, 0, abs_y_max, 0, 0);
    input_set_abs_params(input, ABS_MT_PRESSURE, 0, 255, 0, 0);
    // ABS_MT_TRACKING_ID / ABS_MT_SLOT 由 input_mt_init_slots 自动设置，无需手动

    // 初始化 MT 槽位（Type B 多点协议必需，会自动设置 ABS_MT_SLOT / ABS_MT_TOOL_TYPE）
    ret = input_mt_init_slots(input, 10, 0);
    if (ret) {
        pr_err("vtouch: failed to init MT slots\n");
        input_free_device(input);
        return ret;
    }

    // 直接触摸屏（无指针/光标）
    __set_bit(INPUT_PROP_DIRECT, input->propbit);

    // 注册输入设备
    ret = input_register_device(input);
    if (ret) {
        pr_err("vtouch: failed to register input device\n");
        input_free_device(input);
        return ret;
    }

    dev->input = input;
    dev->touch_active = 0;

    pr_info("vtouch: input device registered, abs range %dx%d (screen %dx%d)\n",
            abs_x_max + 1, abs_y_max + 1, screen_width, screen_height);
    return 0;
}

// 确保虚拟 input 设备已注册（未注册则按当前分辨率创建）
static int vtouch_ensure_input(struct vtouch_dev *dev)
{
    bool created = false;
    int ret = 0;

    mutex_lock(&vtouch_lock);
    if (!dev->input) {
        ret = vtouch_input_init(dev);
        created = (ret == 0);
    }
    mutex_unlock(&vtouch_lock);

    if (created) {
        // InputReader 通过 uevent 发现新设备并打开 event 节点是异步的，
        // 若紧接着发触摸事件，设备还没被打开，事件会丢失。等待枚举完成。
        msleep(50);
    }
    return ret;
}

// 设置屏幕分辨率：更新 abs 范围。
// InputReader 在设备注册时缓存 abs 范围，注册后再改不生效，
// 所以若设备已注册则先注销（下次触摸时按新分辨率重建）。
static int vtouch_set_resolution(struct vtouch_dev *dev, int width, int height)
{
    if (width <= 0 || height <= 0) {
        pr_err("vtouch: invalid resolution %dx%d\n", width, height);
        return -EINVAL;
    }

    mutex_lock(&vtouch_lock);
    screen_width = width;
    screen_height = height;

    // 已注册则注销；随后按新分辨率重建
    if (dev->input) {
        input_unregister_device(dev->input);
        dev->input = NULL;
        dev->touch_active = 0;
        pr_info("vtouch: resolution changed to %dx%d, re-registering input device\n",
                width, height);
    }
    mutex_unlock(&vtouch_lock);

    // 传分辨率即创建虚拟触摸设备（此前未创建或刚注销），getevent 立即可见
    return vtouch_ensure_input(dev);
}

static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void)
{
    int ret;
    
    select_random_device_name();
    
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

    pr_info("vtouch: ready, input device created on ioctl 607 (resolution) or first touch\n");

    pr_info("vtouch: initialized successfully. Device node: /dev/%s\n",
            selected_device_name);

    return 0;
}

static void __exit driver_unload(void)
{
    if (vtouch_device.input)
        input_unregister_device(vtouch_device.input);

    misc_deregister(&misc_dev);
    printk(KERN_INFO "Aurora: Unregistered device: %s\n", selected_device_name);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("1.0");
