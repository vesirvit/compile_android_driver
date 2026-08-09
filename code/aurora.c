#include "aurora.h"
#include <linux/random.h>
#include <linux/string.h>
#include <linux/fcntl.h>

// 触摸事件结构体
struct touch_event {
    int x;
    int y;
    int pressure;
};

// 设备结构体
struct vtouch_dev {
    struct input_dev *input;
    int touch_active;
    int last_x;
    int last_y;
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
    OP_TOUCH_MOVE = 606
};

static const char* device_name_pool[] = {
    "SynapseKernel", "AetherBridge", "NexusGuard", "QuantumLink",
    "VortexCore", "PhantomNode", "TitanShield", "OrionDriver",
    "ZenithPath", "CelestialGate", "NebulaCore", "StellarLink",
    "InfinityHook", "EchoSys", "ChronoFrame", "PulseEngine",
    "ApexBridge", "NovaNode", "SolarFlare", "CosmicPath"
};

#define DEVICE_POOL_SIZE (sizeof(device_name_pool) / sizeof(device_name_pool[0]))
static char selected_device_name[64];
static struct miscdevice misc_dev;
static struct vtouch_dev vtouch_device;

/* ---------- 屏幕分辨率获取 ---------- */
struct drm_modes_dir_ctx {
    struct dir_context ctx;
    char conns[8][32];
    int count;
};

static int drm_modes_dir_fill(struct dir_context *ctx, const char *name, int namlen,
                              loff_t offset, u64 ino, unsigned int d_type)
{
    struct drm_modes_dir_ctx *dctx = container_of(ctx, struct drm_modes_dir_ctx, ctx);
    (void)offset; (void)ino; (void)d_type;

    if (dctx->count >= (int)ARRAY_SIZE(dctx->conns))
        return 1;
    if (namlen <= 0 || namlen >= (int)sizeof(dctx->conns[0]))
        return 0;
    if (strncmp(name, "card", 4) || !strchr(name, '-'))
        return 0;

    memcpy(dctx->conns[dctx->count], name, namlen);
    dctx->conns[dctx->count][namlen] = '\0';
    dctx->count++;
    return 0;
}

/* ---------- kernel_read 兼容层 ---------- */
static inline int safe_kernel_read(struct file *fp, char *buf, size_t size, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    // 5.9+: ssize_t kernel_read(struct file *, void *, size_t, loff_t *)
    return (int)kernel_read(fp, buf, size, pos);
#else
    // 5.8-: ssize_t kernel_read(struct file *, loff_t *, void *, size_t)
    return (int)kernel_read(fp, *pos, buf, size);
#endif
}

static int read_sysfs_modes(const char *conn, int *w, int *h)
{
    char path[128];
    struct file *fp;
    char buf[128];
    loff_t pos = 0;
    int ret;

    snprintf(path, sizeof(path), "/sys/class/drm/%s/modes", conn);
    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp))
        return PTR_ERR(fp);

    ret = safe_kernel_read(fp, buf, sizeof(buf) - 1, &pos);
    filp_close(fp, NULL);
    if (ret <= 0)
        return -EIO;

    buf[ret] = '\0';
    if (sscanf(buf, "%dx%d", w, h) != 2)
        return -EINVAL;

    return 0;
}

static int get_screen_resolution(int *w, int *h)
{
    struct drm_modes_dir_ctx dctx = {
        .ctx.actor = drm_modes_dir_fill,
        .count = 0,
    };
    struct file *dir, *fp;
    char path[128];
    char buf[64];
    loff_t pos = 0;
    int i, ret;

    // 1. DRM sysfs
    dir = filp_open("/sys/class/drm", O_RDONLY | O_DIRECTORY, 0);
    if (!IS_ERR(dir)) {
        iterate_dir(dir, &dctx.ctx);
        filp_close(dir, NULL);

        for (i = 0; i < dctx.count; i++) {
            if (read_sysfs_modes(dctx.conns[i], w, h) == 0)
                return 0;
        }
    }

    // 2. fbdev 兜底
    snprintf(path, sizeof(path), "/sys/class/graphics/fb0/virtual_size");
    fp = filp_open(path, O_RDONLY, 0);
    if (!IS_ERR(fp)) {
        pos = 0;
        ret = safe_kernel_read(fp, buf, sizeof(buf) - 1, &pos);
        filp_close(fp, NULL);
        if (ret > 0) {
            buf[ret] = '\0';
            if (sscanf(buf, "%dx%d", w, h) == 2)
                return 0;
        }
    }

    return -ENODEV;
}

/* ---------- 物理内存操作 ---------- */
static inline bool is_valid_phys_addr(phys_addr_t addr, size_t size)
{
    if (addr + size < addr)
        return false;
    
    if (addr + size > (phys_addr_t)-1)
        return false;
    
    if (!pfn_valid(__phys_to_pfn(addr)))
        return false;
    
    if (size > PAGE_SIZE) {
        phys_addr_t end_addr = addr + size - 1;
        if (!pfn_valid(__phys_to_pfn(end_addr)))
            return false;
    }
    
    return true;
}

/* ---------- 页表遍历（兼容 5.10-6.12） ---------- */
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    phys_addr_t page_addr;
    uintptr_t page_offset;

#if defined(USE_P4D) && defined(CONFIG_ARM64)
    // ARM64 + 5.4+ 使用 p4d
    p4d_t *p4d;
    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    
    pud = pud_offset(p4d, va);
#else
    // ARM32 或旧内核直接 pgd -> pud
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

static bool read_physical_address(phys_addr_t pa, void __user *buffer, size_t size)
{
    void *mapped;
    bool result = false;

    if (!is_valid_phys_addr(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_to_user(buffer, mapped, size) == 0)
        result = true;

    iounmap(mapped);
    return result;
}

static bool write_physical_address(phys_addr_t pa, const void __user *buffer, size_t size)
{
    void *mapped;
    bool result = false;

    if (!is_valid_phys_addr(pa, size))
        return false;

    mapped = ioremap_cache(pa, size);
    if (!mapped)
        return false;

    if (copy_from_user(mapped, buffer, size) == 0)
        result = true;

    iounmap(mapped);
    return result;
}

/* ---------- 进程内存操作 ---------- */
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size)
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
    put_pid(pid_struct);
    
    if (!task)
        return false;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }

    mmap_read_lock(mm);
    pa = translate_linear_address(mm, addr);
    mmap_read_unlock(mm);

    if (pa) {
        result = read_physical_address(pa, buffer, size);
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buffer, size_t size)
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
    put_pid(pid_struct);
    
    if (!task)
        return false;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }

    mmap_read_lock(mm);
    pa = translate_linear_address(mm, addr);
    mmap_read_unlock(mm);

    if (pa) {
        result = write_physical_address(pa, buffer, size);
    }

    mmput(mm);
    put_task_struct(task);
    return result;
}

/* ---------- 模块基址获取（兼容 5.10-6.12） ---------- */
static uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct pid *pid_struct = NULL;
    struct vm_area_struct *vma = NULL;
    uintptr_t base_addr = 0;
    char *path_nm;

    if (!name || strlen(name) == 0)
        return 0;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    
    if (!task)
        return 0;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return 0;
    }

    mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    // 6.1+ 使用 VMA 迭代器
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    // 5.10-6.0 使用传统遍历
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        struct path *path;
        char buf[ARC_PATH_MAX];

        if (!vma->vm_file)
            continue;

        path = &vma->vm_file->f_path;
        path_nm = d_path(path, buf, sizeof(buf));
        if (IS_ERR(path_nm))
            continue;

        if (strstr(path_nm, name) != NULL) {
            char *match = strstr(path_nm, name);
            char next_char = *(match + strlen(name));
            if (next_char == '\0' || next_char == '/') {
                base_addr = vma->vm_start;
                break;
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    
    return base_addr;
}

/* ---------- 触摸功能 ---------- */
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

static void send_touch_event(struct vtouch_dev *dev, int x, int y, int pressure, int active)
{
    if (!dev->input)
        return;

    input_mt_slot(dev->input, 0);
    input_mt_report_slot_state(dev->input, MT_TOOL_FINGER, active);

    if (active) {
        input_report_abs(dev->input, ABS_MT_POSITION_X, x);
        input_report_abs(dev->input, ABS_MT_POSITION_Y, y);
        input_report_abs(dev->input, ABS_MT_PRESSURE, pressure);
    }

    input_report_key(dev->input, BTN_TOUCH, active);
    input_report_key(dev->input, BTN_TOOL_FINGER, active);
    input_sync(dev->input);

    dev->touch_active = active;
    if (active) {
        dev->last_x = x;
        dev->last_y = y;
    }
}

/* ---------- IOCTL 分发 ---------- */
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

    if (dev->touch_active) {
        pr_info("vtouch: auto-releasing touch on close\n");
        send_touch_event(dev, dev->last_x, dev->last_y, 0, 0);
    }

    pr_info("vtouch: device closed\n");
    return 0;
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    static char key[256] = {0};
    static bool is_verified = false;
    
    struct vtouch_dev *dev = file->private_data;
    struct touch_event tev;

    // 权限检查
    if (!capable(CAP_SYS_ADMIN)) {
        pr_warn("vtouch: operation requires CAP_SYS_ADMIN\n");
        return -EPERM;
    }

    if (!dev->input) {
        pr_err("vtouch: input device not initialized\n");
        return -ENODEV;
    }

    switch (cmd) {
        case OP_INIT_KEY: {
            if (!is_verified) {
                if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) == 0) {
                    key[sizeof(key) - 1] = '\0';
                    is_verified = true;
                    pr_info("vtouch: key initialized (len=%zu)\n", strlen(key));
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

            if (strlen(module_name) == 0 || strlen(module_name) >= 64) {
                return -EINVAL;
            }

            mb.base = get_module_base(mb.pid, module_name);

            if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
                return -EFAULT;

            break;
        }

        case OP_TOUCH_PRESS: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            if (tev.x < 0 || tev.y < 0 || tev.pressure < 0 || tev.pressure > 255)
                return -EINVAL;

            pr_info("vtouch: PRESS at (%d, %d) pressure=%d\n", tev.x, tev.y, tev.pressure);
            send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
            break;
        }

        case OP_TOUCH_RELEASE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            pr_info("vtouch: RELEASE at (%d, %d)\n", tev.x, tev.y);
            send_touch_event(dev, tev.x, tev.y, 0, 0);
            break;
        }

        case OP_TOUCH_MOVE: {
            if (copy_from_user(&tev, (void __user *)arg, sizeof(tev)))
                return -EFAULT;

            if (!dev->touch_active) {
                pr_warn("vtouch: MOVE called but touch is not active\n");
                return -EINVAL;
            }

            if (tev.x < 0 || tev.y < 0 || tev.pressure < 0 || tev.pressure > 255)
                return -EINVAL;

            pr_info("vtouch: MOVE to (%d, %d) pressure=%d\n", tev.x, tev.y, tev.pressure);
            send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
            break;
        }

        default: {
            return -ENOTTY;
        }
    }

    return 0;
}

/* ---------- 输入设备初始化 ---------- */
static int vtouch_input_init(struct vtouch_dev *dev)
{
    struct input_dev *input;
    int screen_w, screen_h;
    int ret;

    input = input_allocate_device();
    if (!input) {
        pr_err("vtouch: failed to allocate input device\n");
        return -ENOMEM;
    }

    input->name = "Virtual Touchscreen";
    input->id.bustype = BUS_VIRTUAL;
    input->id.vendor = 0x1234;
    input->id.product = 0x5678;
    input->id.version = 0x0001;

    __set_bit(EV_ABS, input->evbit);
    __set_bit(EV_SYN, input->evbit);
    __set_bit(EV_KEY, input->evbit);

    __set_bit(BTN_TOUCH, input->keybit);
    __set_bit(BTN_TOOL_FINGER, input->keybit);

    screen_w = 1023;
    screen_h = 1023;
    if (get_screen_resolution(&screen_w, &screen_h) == 0) {
        pr_info("vtouch: using screen resolution %dx%d\n", screen_w, screen_h);
    } else {
        pr_warn("vtouch: failed to read screen resolution, fallback to %dx%d\n", screen_w, screen_h);
    }
    
    input_set_abs_params(input, ABS_MT_POSITION_X, 0, screen_w, 0, 0);
    input_set_abs_params(input, ABS_MT_POSITION_Y, 0, screen_h, 0, 0);
    input_set_abs_params(input, ABS_MT_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input, ABS_MT_TRACKING_ID, -1, 65535, 0, 0);

    ret = input_mt_init_slots(input, 10, 0);
    if (ret) {
        pr_err("vtouch: failed to init MT slots\n");
        input_free_device(input);
        return ret;
    }

    __set_bit(INPUT_PROP_DIRECT, input->propbit);

    ret = input_register_device(input);
    if (ret) {
        pr_err("vtouch: failed to register input device\n");
        input_free_device(input);
        return ret;
    }

    dev->input = input;
    dev->touch_active = 0;
    dev->last_x = 0;
    dev->last_y = 0;

    pr_info("vtouch: input device registered\n");
    return 0;
}

/* ---------- 文件操作结构体 ---------- */
static const struct file_operations dispatch_fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

/* ---------- 模块加载/卸载 ---------- */
static int __init driver_entry(void)
{
    int ret;
    
    select_random_device_name();
    
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

    ret = vtouch_input_init(&vtouch_device);
    if (ret) {
        misc_deregister(&misc_dev);
        return ret;
    }

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

MODULE_DESCRIPTION("Linux Kernel Module (5.10-6.12 Compatible)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_VERSION("2.1");

/* VFS 符号在 5.14+ 内核中被导出到该命名空间，外部模块需显式 import */
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);