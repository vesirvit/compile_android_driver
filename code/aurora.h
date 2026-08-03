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

/* 架构相关 */
#include <asm/io.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <asm/pgalloc.h>
#endif
#include <asm/pgtable.h>

/* Linux 6.1+ 使用新的 VMA 迭代器接口 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#endif

#define VTouchName "vtouch"
#define VTouchClass "vtouch_class"

#endif /* AURORA_H */
