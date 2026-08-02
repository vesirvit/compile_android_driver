// vtouch.h - Virtual Touchscreen 驱动头文件
#ifndef _VTOUCH_H
#define _VTOUCH_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/err.h>
#include <linux/version.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#define DEVICE_NAME "vtouch"
#define CLASS_NAME "vtouch_class"

// IOCTL命令定义
#define TOUCH_IOC_MAGIC 't'
#define TOUCH_IOC_PRESS _IOW(TOUCH_IOC_MAGIC, 1, struct touch_event)
#define TOUCH_IOC_RELEASE _IOW(TOUCH_IOC_MAGIC, 2, struct touch_event)
#define TOUCH_IOC_MOVE _IOW(TOUCH_IOC_MAGIC, 3, struct touch_event)

// 触摸事件结构体
struct touch_event {
    int x;          // X坐标 (0-1023)
    int y;          // Y坐标 (0-1023)
    int pressure;   // 压力值 (0-255)
};

// 设备结构体
struct vtouch_dev {
    struct cdev cdev;
    struct device *device;
    struct input_dev *input;
    int touch_active;
    int last_x;
    int last_y;
};

#endif /* _VTOUCH_H */
