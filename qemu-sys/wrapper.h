// OS includes
#include <qemu/osdep.h>

#if defined(TARGET_ARM)
// CPUARMState, NVIC
#include <hw/arm/armv7m.h>
// qdev_connect_clock_in
#include <hw/qdev-clock.h>
// raise_exception
#include <target/arm/internals.h>
// arm_register_el_change_hook
#include <target/arm/cpu.h>
#endif

// MachineClass
#include <hw/boards.h>

// get_system_memory
#include <hw/loader.h>

// qemu_target_page_*
#include <exec/target_page.h>

// TranslationBlock, GETPC_ADJ
#include <exec/exec-all.h>

// cpu_io_recompile
#include <accel/tcg/internal.h>

// qdev_prop_set_string
#include <hw/misc/unimp.h>

// set_basic_block_hook, tcg_prologue_init
#include <tcg/tcg.h>
// TCGHelperInfo
#include <tcg/tcg-internal.h>
// dh_*flag_*
#include <exec/helper-head.h>
// DisasContextBase
#include <exec/translator.h>

// MO_*
#include <exec/memop.h>

// qemu_* functions
#include <sysemu/runstate.h>
#include <sysemu/sysemu.h>

// AccelClass
#include <qemu/accel.h>

// tcg_allowed
#include <sysemu/tcg.h>

// tcg_cpu_init_cflags
#include <accel/tcg/tcg-accel-ops.h>

// TCGCPUOps
#include <hw/core/tcg-cpu-ops.h>

// tcg_exec_init
#include <sysemu/tcg.h>

// cpus_register_accel
#include <sysemu/cpus.h>

// cpu_exec_step_atomic
#include <exec/cpu-common.h>

// qemu_guest_random_seed_thread_part2
#include <qemu/guest-random.h>

// current_machine
#include <hw/boards.h>

// DirtyBitmapSnapshot
#include "softmmu/physmem.c"