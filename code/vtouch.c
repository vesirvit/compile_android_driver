#include "vtouch.h"

static struct vtouch_dev *vtouch_device;
static struct class *vtouch_class;
static dev_t dev_num;

// 发送触摸事件
static void send_touch_event(struct vtouch_dev *dev, int x, int y, int pressure, int active)
{
    if (!dev->input)
        return;

    // 上报X坐标
    input_report_abs(dev->input, ABS_MT_POSITION_X, x);
    // 上报Y坐标
    input_report_abs(dev->input, ABS_MT_POSITION_Y, y);
    // 上报压力值
    input_report_abs(dev->input, ABS_MT_PRESSURE, pressure);
    // 上报跟踪ID（用于多点触摸，这里固定为0）
    input_report_abs(dev->input, ABS_MT_TRACKING_ID, 0);
    
    // 上报触摸槽位
    input_mt_slot(dev->input, 0);
    input_mt_report_slot_state(dev->input, MT_TOOL_FINGER, active);
    
    // 同步事件
    input_sync(dev->input);
    
    // 保存当前状态
    dev->touch_active = active;
    if (active) {
        dev->last_x = x;
        dev->last_y = y;
    }
}

// IOCTL处理函数
static long vtouch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct vtouch_dev *dev = file->private_data;
    struct touch_event tev;
    int ret = 0;

    if (!dev->input) {
        pr_err("vtouch: input device not initialized\n");
        return -ENODEV;
    }

    switch (cmd) {
    case TOUCH_IOC_PRESS:
        if (copy_from_user(&tev, (void __user *)arg, sizeof(tev))) {
            ret = -EFAULT;
            break;
        }
        pr_info("vtouch: PRESS at (%d, %d) pressure=%d\n", tev.x, tev.y, tev.pressure);
        send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
        break;

    case TOUCH_IOC_RELEASE:
        if (copy_from_user(&tev, (void __user *)arg, sizeof(tev))) {
            ret = -EFAULT;
            break;
        }
        pr_info("vtouch: RELEASE at (%d, %d)\n", tev.x, tev.y);
        send_touch_event(dev, tev.x, tev.y, 0, 0);
        break;

    case TOUCH_IOC_MOVE:
        if (copy_from_user(&tev, (void __user *)arg, sizeof(tev))) {
            ret = -EFAULT;
            break;
        }
        if (!dev->touch_active) {
            pr_warn("vtouch: MOVE called but touch is not active\n");
            ret = -EINVAL;
            break;
        }
        pr_info("vtouch: MOVE to (%d, %d) pressure=%d\n", tev.x, tev.y, tev.pressure);
        send_touch_event(dev, tev.x, tev.y, tev.pressure, 1);
        break;

    default:
        pr_err("vtouch: unknown ioctl command %d\n", cmd);
        ret = -ENOTTY;
        break;
    }

    return ret;
}

// 打开设备
static int vtouch_open(struct inode *inode, struct file *file)
{
    struct vtouch_dev *dev;
    dev = container_of(inode->i_cdev, struct vtouch_dev, cdev);
    file->private_data = dev;
    pr_info("vtouch: device opened\n");
    return 0;
}

// 关闭设备
static int vtouch_release(struct inode *inode, struct file *file)
{
    struct vtouch_dev *dev = file->private_data;
    
    // 如果触摸还处于激活状态，自动释放
    if (dev->touch_active) {
        pr_info("vtouch: auto-releasing touch on close\n");
        send_touch_event(dev, dev->last_x, dev->last_y, 0, 0);
    }
    
    pr_info("vtouch: device closed\n");
    return 0;
}

// 文件操作结构体
static const struct file_operations vtouch_fops = {
    .owner = THIS_MODULE,
    .open = vtouch_open,
    .release = vtouch_release,
    .unlocked_ioctl = vtouch_ioctl,
};

// 初始化输入设备
static int vtouch_input_init(struct vtouch_dev *dev)
{
    struct input_dev *input;
    int ret;

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

    // 设置绝对坐标范围
    input_set_abs_params(input, ABS_MT_POSITION_X, 0, 1023, 0, 0);
    input_set_abs_params(input, ABS_MT_POSITION_Y, 0, 1023, 0, 0);
    input_set_abs_params(input, ABS_MT_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input, ABS_MT_TRACKING_ID, -1, 65535, 0, 0);

    // 设置多点触摸参数
    input_set_abs_params(input, ABS_MT_SLOT, 0, 9, 0, 0);
    input_set_abs_params(input, ABS_MT_TOOL_TYPE, 0, 1, 0, 0);
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
    dev->last_x = 0;
    dev->last_y = 0;

    pr_info("vtouch: input device registered\n");
    return 0;
}

// 模块初始化
static int __init vtouch_init(void)
{
    int ret;

    pr_info("vtouch: initializing virtual touch device\n");

    // 动态分配设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("vtouch: failed to allocate device number\n");
        return ret;
    }

    // 创建设备类
    vtouch_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(vtouch_class)) {
        pr_err("vtouch: failed to create class\n");
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(vtouch_class);
    }

    // 分配设备结构体
    vtouch_device = kzalloc(sizeof(struct vtouch_dev), GFP_KERNEL);
    if (!vtouch_device) {
        pr_err("vtouch: failed to allocate device structure\n");
        class_destroy(vtouch_class);
        unregister_chrdev_region(dev_num, 1);
        return -ENOMEM;
    }

    // 初始化字符设备
    cdev_init(&vtouch_device->cdev, &vtouch_fops);
    vtouch_device->cdev.owner = THIS_MODULE;

    // 添加字符设备
    ret = cdev_add(&vtouch_device->cdev, dev_num, 1);
    if (ret) {
        pr_err("vtouch: failed to add char device\n");
        kfree(vtouch_device);
        class_destroy(vtouch_class);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    // 创建设备节点
    vtouch_device->device = device_create(vtouch_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(vtouch_device->device)) {
        pr_err("vtouch: failed to create device\n");
        cdev_del(&vtouch_device->cdev);
        kfree(vtouch_device);
        class_destroy(vtouch_class);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(vtouch_device->device);
    }

    // 初始化输入设备
    ret = vtouch_input_init(vtouch_device);
    if (ret) {
        device_destroy(vtouch_class, dev_num);
        cdev_del(&vtouch_device->cdev);
        kfree(vtouch_device);
        class_destroy(vtouch_class);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    pr_info("vtouch: initialized successfully. Device node: /dev/%s\n", DEVICE_NAME);
    return 0;
}

// 模块退出
static void __exit vtouch_exit(void)
{
    pr_info("vtouch: exiting\n");

    if (vtouch_device) {
        // 确保触摸已经释放
        if (vtouch_device->touch_active) {
            send_touch_event(vtouch_device, 0, 0, 0, 0);
        }

        // 注销输入设备
        if (vtouch_device->input) {
            input_unregister_device(vtouch_device->input);
            // input_unregister_device 会自动调用 input_free_device
        }

        // 销毁设备
        device_destroy(vtouch_class, dev_num);
        cdev_del(&vtouch_device->cdev);
        kfree(vtouch_device);
    }

    class_destroy(vtouch_class);
    unregister_chrdev_region(dev_num, 1);

    pr_info("vtouch: cleaned up\n");
}

module_init(vtouch_init);
module_exit(vtouch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YihanChan");
MODULE_DESCRIPTION("Virtual Touchscreen Device");
MODULE_VERSION("1.0");
