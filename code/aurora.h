#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>

#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#else
#include <asm/pgtable.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#endif

// perf硬件断点相关
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

// 硬件断点结构定义
typedef struct _HW_BREAKPOINT {
    pid_t pid;                    // 目标线程PID
    uintptr_t addr;                // 断点地址
    int type;                      // 断点类型 (HW_BREAKPOINT_X, HW_BREAKPOINT_R, HW_BREAKPOINT_W)
    int len;                       // 断点长度 (1,2,4,8)
} HW_BREAKPOINT, *PHW_BREAKPOINT;

// 全局Hook PC值声明
extern atomic64_t g_hook_pc;