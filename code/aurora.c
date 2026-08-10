#include "aurora.h"
#include <linux/random.h>
#include <linux/slab.h>

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

// 挂到真实触摸屏的 handler/handle（不注册任何新设备）
static struct input_handler vtouch_handler;
static struct input_handle *vtouch_handle;

// 脚本注入状态：tracking id 从 200 起（远离人手的小 id），slot 用最后一个
static int vtouch_tracking_id = 200;
static int vtouch_slot;
static bool vtouch_active;

// 屏幕分辨率（屏幕像素），由 607 传入；未设置时坐标透传并按触摸屏 abs 范围 clamp
static int screen_width;
static int screen_height;


static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static void send_touch_event(unsigned int action, int x, int y);
static int vtouch_scale_axis(struct input_dev *dev, unsigned int axis,
                             int value, int screen_max);
static int vtouch_connect(struct input_handler *handler, struct input_dev *dev,
                          const struct input_device_id *id);
static void vtouch_disconnect(struct input_handle *handle);
static bool vtouch_input_init(void);
static void vtouch_input_exit(void);
static int vtouch_set_resolution(int width, int height);

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

// 发送触摸事件（注入真实触摸屏，与人手共存）
// action: 604 按下 / 605 抬起 / 606 移动；x/y 为屏幕像素坐标
// 共存关键：
//   1. 脚本用最后一个 slot + 大 tracking id，与人手（通常 slot 0）不冲突；
//   2. BTN_TOUCH 只在设备当前无手指时置 1，抬起时不主动清 0 ——
//      人手按着时脚本抬起不会把整根手指的状态抹掉。
static void send_touch_event(unsigned int action, int x, int y)
{
    struct input_dev *dev;
    bool is_mt;
    int sx, sy;

    if (!vtouch_handle || !vtouch_handle->dev)
        return;

    dev = vtouch_handle->dev;
    is_mt = test_bit(ABS_MT_SLOT, dev->absbit) ||
            test_bit(ABS_MT_POSITION_X, dev->absbit);

    if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
        sx = vtouch_scale_axis(dev, ABS_MT_POSITION_X, x, screen_width - 1);
        sy = vtouch_scale_axis(dev, ABS_MT_POSITION_Y, y, screen_height - 1);
    } else {
        sx = vtouch_scale_axis(dev, ABS_X, x, screen_width - 1);
        sy = vtouch_scale_axis(dev, ABS_Y, y, screen_height - 1);
    }

    switch (action) {
    case OP_TOUCH_PRESS:
        if (test_bit(ABS_MT_SLOT, dev->absbit)) {
            // MT 协议 B：用最后一个 slot，避免与人手（slot 0）冲突
            vtouch_slot = input_abs_get_max(dev, ABS_MT_SLOT);
            input_event(dev, EV_ABS, ABS_MT_SLOT, vtouch_slot);
            input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, vtouch_tracking_id++);
            input_event(dev, EV_ABS, ABS_MT_POSITION_X, sx);
            input_event(dev, EV_ABS, ABS_MT_POSITION_Y, sy);
            if (test_bit(ABS_MT_TOUCH_MAJOR, dev->absbit))
                input_event(dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 10);
            if (test_bit(ABS_MT_PRESSURE, dev->absbit)) {
                int p = input_abs_get_max(dev, ABS_MT_PRESSURE);
                input_event(dev, EV_ABS, ABS_MT_PRESSURE, p > 1 ? p / 2 : 1);
            }
        } else if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
            // MT 协议 A
            input_event(dev, EV_ABS, ABS_MT_POSITION_X, sx);
            input_event(dev, EV_ABS, ABS_MT_POSITION_Y, sy);
            input_event(dev, EV_SYN, SYN_MT_REPORT, 0);
        } else {
            // 单点触摸
            input_event(dev, EV_ABS, ABS_X, sx);
            input_event(dev, EV_ABS, ABS_Y, sy);
        }
        // BTN_TOUCH：设备当前无手指才置 1（人手按着时保持原状）
        if (is_mt) {
            if (!test_bit(BTN_TOUCH, dev->key))
                input_event(dev, EV_KEY, BTN_TOUCH, 1);
            if (test_bit(BTN_TOOL_FINGER, dev->keybit) &&
                !test_bit(BTN_TOOL_FINGER, dev->key))
                input_event(dev, EV_KEY, BTN_TOOL_FINGER, 1);
        } else {
            input_event(dev, EV_KEY, BTN_TOUCH, 1);
        }
        break;

    case OP_TOUCH_RELEASE:
        if (test_bit(ABS_MT_SLOT, dev->absbit)) {
            input_event(dev, EV_ABS, ABS_MT_SLOT, vtouch_slot);
            input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        } else if (!is_mt) {
            // 单点设备：脚本抬起 = 全部抬起
            input_event(dev, EV_KEY, BTN_TOUCH, 0);
        }
        // MT 设备抬起时不主动清 BTN_TOUCH，由人手状态决定
        break;

    case OP_TOUCH_MOVE:
        if (test_bit(ABS_MT_SLOT, dev->absbit)) {
            input_event(dev, EV_ABS, ABS_MT_SLOT, vtouch_slot);
            input_event(dev, EV_ABS, ABS_MT_POSITION_X, sx);
            input_event(dev, EV_ABS, ABS_MT_POSITION_Y, sy);
            if (test_bit(ABS_MT_PRESSURE, dev->absbit)) {
                int p = input_abs_get_max(dev, ABS_MT_PRESSURE);
                input_event(dev, EV_ABS, ABS_MT_PRESSURE, p > 1 ? p / 2 : 1);
            }
        } else if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
            input_event(dev, EV_ABS, ABS_MT_POSITION_X, sx);
            input_event(dev, EV_ABS, ABS_MT_POSITION_Y, sy);
            input_event(dev, EV_SYN, SYN_MT_REPORT, 0);
        } else {
            input_event(dev, EV_ABS, ABS_X, sx);
            input_event(dev, EV_ABS, ABS_Y, sy);
        }
        break;

    default:
        return;
    }

    input_sync(dev);
    vtouch_active = (action == OP_TOUCH_PRESS || action == OP_TOUCH_MOVE);
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
    (void)file;

    pr_info("vtouch: device opened\n");
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    (void)node;
    (void)file;

    // 脚本 fd 关闭时如果注入的触摸还按着，自动补一个抬起
    if (vtouch_active) {
        pr_info("vtouch: auto-releasing touch on close\n");
        send_touch_event(OP_TOUCH_RELEASE, 0, 0);
    }

    pr_info("vtouch: device closed\n");

    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    static char key[256] = {0};
    static bool is_verified = false;
    
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
            ret = vtouch_set_resolution(sr.width, sr.height);
            if (ret)
                return ret;
            break;
        }

        case OP_TOUCH_PRESS: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            if (!vtouch_handle || !vtouch_handle->dev)
                return -EIO;

            pr_info("vtouch: ioctl PRESS x=%d y=%d pressure=%d (screen %dx%d)\n",
                    tev.x, tev.y, tev.pressure, screen_width, screen_height);
            send_touch_event(OP_TOUCH_PRESS, tev.x, tev.y);
            break;
        }

        case OP_TOUCH_RELEASE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            if (!vtouch_handle || !vtouch_handle->dev)
                return -EIO;

            pr_info("vtouch: ioctl RELEASE x=%d y=%d (screen %dx%d)\n",
                    tev.x, tev.y, screen_width, screen_height);
            send_touch_event(OP_TOUCH_RELEASE, tev.x, tev.y);
            break;
        }

        case OP_TOUCH_MOVE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            if (!vtouch_handle || !vtouch_handle->dev)
                return -EIO;

            if (!vtouch_active) {
                pr_warn("vtouch: ioctl MOVE called but touch is not active\n");
                return -EINVAL;
            }
            pr_info("vtouch: ioctl MOVE x=%d y=%d pressure=%d (screen %dx%d)\n",
                    tev.x, tev.y, tev.pressure, screen_width, screen_height);
            send_touch_event(OP_TOUCH_MOVE, tev.x, tev.y);
            break;
        }

        default: {
            return -ENOTTY;
        }
    }

    return 0;
}

// ===== 劫持注入：挂接真实触摸屏，脚本事件注入其队列（不注册新设备） =====
// 匹配条件：有 ABS_MT_POSITION_X/Y 或 ABS_X/Y 的触摸设备（不强制 BTN_TOUCH）
static const struct input_device_id vtouch_ids[] = {
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                 INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_ABS) },
        .absbit = { BIT_MASK(ABS_MT_POSITION_X) | BIT_MASK(ABS_MT_POSITION_Y) },
    },
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                 INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_ABS) },
        .absbit = { BIT_MASK(ABS_X) | BIT_MASK(ABS_Y) },
    },
    { }
};
MODULE_DEVICE_TABLE(input, vtouch_ids);

// 把屏幕像素坐标（0 ~ screen_max）映射到目标设备的原始坐标范围；
// screen_max <= 0 时按原样透传（未设置分辨率时兜底），越界 clamp 到设备范围
static int vtouch_scale_axis(struct input_dev *dev, unsigned int axis,
                             int value, int screen_max)
{
    int min, max;

    min = input_abs_get_min(dev, axis);
    max = input_abs_get_max(dev, axis);
    if (max <= min)
        return 0;

    if (screen_max > 0)
        value = min + (value * (max - min)) / screen_max;

    if (value < min)
        value = min;
    if (value > max)
        value = max;
    return value;
}

static int vtouch_connect(struct input_handler *handler, struct input_dev *dev,
                          const struct input_device_id *id)
{
    struct input_handle *handle;

    // 只挂第一个触摸屏
    if (vtouch_handle)
        return 0;

    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;

    handle->dev = dev;
    handle->handler = handler;
    handle->name = "aurora-vtouch";

    if (input_register_handle(handle)) {
        kfree(handle);
        return -ENOMEM;
    }

    vtouch_handle = handle;
    pr_info("vtouch: attached to real touchscreen [%s], "
            "inject on last slot, tracking id from %d\n",
            dev->name, vtouch_tracking_id);
    return 0;
}

static void vtouch_disconnect(struct input_handle *handle)
{
    if (handle == vtouch_handle)
        vtouch_handle = NULL;
    input_unregister_handle(handle);
    kfree(handle);
}

static bool vtouch_input_init(void)
{
    vtouch_handler.name = "aurora-vtouch";
    vtouch_handler.connect = vtouch_connect;
    vtouch_handler.disconnect = vtouch_disconnect;
    vtouch_handler.id_table = vtouch_ids;

    if (input_register_handler(&vtouch_handler)) {
        pr_err("vtouch: failed to register touch handler\n");
        return false;
    }

    if (!vtouch_handle) {
        pr_warn("vtouch: no touchscreen device found\n");
    } else {
        pr_info("vtouch: touch hijack ready\n");
    }
    return true;
}

static void vtouch_input_exit(void)
{
    input_unregister_handler(&vtouch_handler);
    vtouch_handle = NULL;
}

// 设置屏幕分辨率（607），用于坐标点对点换算；未设置时透传 + clamp
static int vtouch_set_resolution(int width, int height)
{
    if (width <= 0 || height <= 0) {
        pr_err("vtouch: invalid resolution %dx%d\n", width, height);
        return -EINVAL;
    }

    screen_width = width;
    screen_height = height;
    pr_info("vtouch: screen resolution set to %dx%d\n", width, height);
    return 0;
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

    pr_info("vtouch: hijack mode, attached to real touchscreen\n");

    // 挂接真实触摸屏（失败不阻塞模块加载，触摸 ioctl 会返回 -EIO）
    if (!vtouch_input_init()) {
        pr_err("vtouch: failed to init touch injection\n");
    }

    pr_info("vtouch: initialized successfully. Device node: /dev/%s\n",
            selected_device_name);

    return 0;
}

static void __exit driver_unload(void)
{
    vtouch_input_exit();

    misc_deregister(&misc_dev);
    printk(KERN_INFO "Aurora: Unregistered device: %s\n", selected_device_name);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("1.0");
