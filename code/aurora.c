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

typedef struct _TOUCH_EVENT {
    int x;  // 屏幕像素坐标：0 ~ 屏幕宽-1
    int y;  // 屏幕像素坐标：0 ~ 屏幕高-1
} TOUCH_EVENT, *PTOUCH_EVENT;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_TOUCH_PRESS = 0x804,
    OP_TOUCH_RELEASE = 0x805,
    OP_TOUCH_MOVE = 0x806,
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
static struct input_handler vtouch_handler;
static struct input_handle *vtouch_handle;
static int vtouch_tracking_id = 200;
static int screen_width;
static int screen_height;

static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size);
static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size);
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size);
static uintptr_t get_module_base(pid_t pid, const char *name);
static bool read_file_resolution(const char *path, int *w, int *h);
static bool get_screen_resolution(int *w, int *h);
static void vtouch_update_screen_from_dev(struct input_dev *dev);
static int vtouch_scale_axis(struct input_dev *dev, unsigned int axis,
                             int value, int screen_max);
static void send_touch_event(unsigned int action, int x, int y);
static int vtouch_connect(struct input_handler *handler, struct input_dev *dev,
                          const struct input_device_id *id);
static void vtouch_disconnect(struct input_handle *handle);
static bool vtouch_input_init(void);
static void vtouch_input_exit(void);

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

// ===== 虚拟触摸屏（不注册设备，直接劫持现有触摸屏） =====
// Android 目标机已有真实触摸屏 input 设备（evdev 节点 /dev/input/eventX）。
// 本模块不注册任何新 input 设备（getevent / /proc/bus/input/devices 里不会出现新设备），
// 而是通过 input_handler 挂到现有触摸屏上，用 input_event() 把按下/移动/抬起事件
// 注入到该设备的 evdev 队列，走的是和真实驱动完全相同的通道，系统无法区分真伪。
// 坐标点对点：驱动加载时读取屏幕分辨率，用户态传屏幕像素坐标，内核按目标设备 abs 范围换算。
static bool read_file_resolution(const char *path, int *w, int *h)
{
    struct file *fp;
    char buf[128];
    loff_t pos = 0;
    ssize_t len;
    int a = 0, b = 0;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp))
        return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
    len = kernel_read(fp, buf, sizeof(buf) - 1, &pos);
#else
    len = kernel_read(fp, 0, buf, sizeof(buf) - 1);
#endif
    filp_close(fp, NULL);

    if (len <= 0)
        return false;

    buf[len] = '\0';
    if (sscanf(buf, "%dx%d", &a, &b) == 2 && a > 0 && b > 0) {
        *w = a;
        *h = b;
        return true;
    }
    if (sscanf(buf, "%d,%d", &a, &b) == 2 && a > 0 && b > 0) {
        *w = a;
        *h = b;
        return true;
    }
    return false;
}

static bool get_screen_resolution(int *w, int *h)
{
    static const char *fb_paths[] = {
        "/sys/class/graphics/fb0/virtual_size",
    };
    static const char *drm_paths[] = {
        "/sys/class/drm/card0-DSI-1/modes",
        "/sys/class/drm/card0-DSI-0/modes",
        "/sys/class/drm/card0-DSI-2/modes",
        "/sys/class/drm/card0-eDP-1/modes",
        "/sys/class/drm/card0-DP-1/modes",
        "/sys/class/drm/card0-HDMI-A-1/modes",
        "/sys/class/drm/card1-DSI-1/modes",
    };
    int i;

    for (i = 0; i < ARRAY_SIZE(fb_paths); i++) {
        if (read_file_resolution(fb_paths[i], w, h))
            return true;
    }

    for (i = 0; i < ARRAY_SIZE(drm_paths); i++) {
        if (read_file_resolution(drm_paths[i], w, h))
            return true;
    }

    return false;
}
static const struct input_device_id vtouch_ids[] = {
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                 INPUT_DEVICE_ID_MATCH_KEYBIT |
                 INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_ABS) },
        .keybit = { BIT_MASK(BTN_TOUCH) },
        .absbit = { BIT_MASK(ABS_MT_POSITION_X) | BIT_MASK(ABS_MT_POSITION_Y) },
    },
    {
        .flags = INPUT_DEVICE_ID_MATCH_EVBIT |
                 INPUT_DEVICE_ID_MATCH_KEYBIT |
                 INPUT_DEVICE_ID_MATCH_ABSBIT,
        .evbit = { BIT_MASK(EV_ABS) },
        .keybit = { BIT_MASK(BTN_TOUCH) },
        .absbit = { BIT_MASK(ABS_X) | BIT_MASK(ABS_Y) },
    },
    { }
};
MODULE_DEVICE_TABLE(input, vtouch_ids);

// 把用户态屏幕像素坐标（0 ~ screen_max）映射到目标设备的原始坐标范围；
// screen_max <= 0 时按原样透传（仅在读不到屏幕分辨率时兜底）
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

// 读不到屏幕分辨率时，用触摸屏自身坐标范围作为屏幕大小（系统按该范围映射屏幕，等效点对点）
static void vtouch_update_screen_from_dev(struct input_dev *dev)
{
    unsigned int ax = ABS_X, ay = ABS_Y;

    if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
        ax = ABS_MT_POSITION_X;
        ay = ABS_MT_POSITION_Y;
    }

    if (screen_width <= 0)
        screen_width = input_abs_get_max(dev, ax) + 1;
    if (screen_height <= 0)
        screen_height = input_abs_get_max(dev, ay) + 1;
}

static int vtouch_connect(struct input_handler *handler, struct input_dev *dev,
                          const struct input_device_id *id)
{
    struct input_handle *handle;

    // 已持有目标触摸屏则忽略其他设备
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

    // 若加载时未读到屏幕分辨率，用触摸屏自身范围兜底
    vtouch_update_screen_from_dev(dev);

    printk(KERN_INFO "Aurora: Touch hijack attached to: %s (%dx%d)\n",
           dev->name, screen_width, screen_height);
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

    // 加载时读取屏幕分辨率，初始化点对点触摸
    if (get_screen_resolution(&screen_width, &screen_height)) {
        printk(KERN_INFO "Aurora: Screen resolution: %dx%d\n",
               screen_width, screen_height);
    } else {
        printk(KERN_WARNING "Aurora: Failed to read screen resolution, "
               "will fallback to touch device range\n");
    }

    if (input_register_handler(&vtouch_handler)) {
        printk(KERN_ERR "Aurora: Failed to register touch handler\n");
        return false;
    }

    if (!vtouch_handle) {
        printk(KERN_WARNING "Aurora: No touchscreen device found\n");
    } else {
        printk(KERN_INFO "Aurora: Touch hijack ready\n");
    }
    return true;
}

static void send_touch_event(unsigned int action, int x, int y)
{
    struct input_dev *dev;
    int sx, sy;

    if (!vtouch_handle || !vtouch_handle->dev)
        return;

    dev = vtouch_handle->dev;

    // 按目标设备的实际协议选择坐标轴（x/y 为屏幕像素坐标，点对点换算）
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
            // MT 协议 B（现代 Android 触摸屏），用最后一个 slot 减少与真实手指冲突
            int slot = input_abs_get_max(dev, ABS_MT_SLOT);

            input_event(dev, EV_ABS, ABS_MT_SLOT, slot);
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
            // 普通单点触摸
            input_event(dev, EV_ABS, ABS_X, sx);
            input_event(dev, EV_ABS, ABS_Y, sy);
        }
        input_event(dev, EV_KEY, BTN_TOUCH, 1);
        if (test_bit(BTN_TOOL_FINGER, dev->keybit))
            input_event(dev, EV_KEY, BTN_TOOL_FINGER, 1);
        break;

    case OP_TOUCH_RELEASE:
        if (test_bit(ABS_MT_SLOT, dev->absbit)) {
            input_event(dev, EV_ABS, ABS_MT_SLOT,
                       input_abs_get_max(dev, ABS_MT_SLOT));
            input_event(dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        }
        input_event(dev, EV_KEY, BTN_TOUCH, 0);
        if (test_bit(BTN_TOOL_FINGER, dev->keybit))
            input_event(dev, EV_KEY, BTN_TOOL_FINGER, 0);
        break;

    case OP_TOUCH_MOVE:
        if (test_bit(ABS_MT_POSITION_X, dev->absbit)) {
            input_event(dev, EV_ABS, ABS_MT_POSITION_X, sx);
            input_event(dev, EV_ABS, ABS_MT_POSITION_Y, sy);
            if (!test_bit(ABS_MT_SLOT, dev->absbit))
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
}

static void vtouch_input_exit(void)
{
    input_unregister_handler(&vtouch_handler);
    vtouch_handle = NULL;
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

    case OP_TOUCH_PRESS:
    case OP_TOUCH_RELEASE:
    case OP_TOUCH_MOVE: {
        TOUCH_EVENT te;

        if (!vtouch_handle || !vtouch_handle->dev)
            return -EIO;

        if (copy_from_user(&te, (void __user *)arg, sizeof(te)))
            return -EFAULT;

        send_touch_event(cmd, te.x, te.y);
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
    
    select_random_device_name();
    
    // 初始化触摸注入（失败不阻塞模块加载，触摸 ioctl 会返回 -EIO）
    if (!vtouch_input_init()) {
        printk(KERN_ERR "Aurora: Failed to init touch injection\n");
    }
    
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

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_DESCRIPTION("Linux Kernel Module");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("1.0");
