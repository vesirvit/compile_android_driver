#ifndef AURORA_H
#define AURORA_H

/* 模块基础 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>

/* 设备与文件系统 */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/input.h>
#include <linux/input/mt.h>

/* 内存与进程 */
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/dcache.h>

/* 架构相关 */
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

/* VMA 迭代器 (6.1+) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#endif

/* 内核版本宏定义 */
#define KERNEL_VER(major, minor, patch) \
    KERNEL_VERSION(major, minor, patch)

/* 判断是否需要 p4d (5.4 以上，且是 64位) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#define USE_P4D
#endif

#define VTouchName "vtouch"
#define VTouchClass "vtouch_class"
#define ARC_PATH_MAX 256

#endif /* AURORA_H */