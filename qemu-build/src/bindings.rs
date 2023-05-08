use std::path::Path;

use bindgen::{BindgenError, Bindings};

use crate::Arch;

pub fn generate(qemu_dir: &Path, build_dir: &Path, arch: Arch) -> Result<Bindings, BindgenError> {
    let bindings = bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        .header("wrapper.h")
        .clang_args(crate::qemu_bindgen_clang_args(qemu_dir, build_dir, arch))
        .allowlist_function("add_tcg_function")
        .allowlist_function("cpu_can_run")
        .allowlist_function("cpu_create")
        .allowlist_function("cpu_exec_end")
        .allowlist_function("cpu_exec_start")
        .allowlist_function("cpu_exec_step_atomic")
        .allowlist_function("cpu_exec")
        .allowlist_function("cpu_exit")
        .allowlist_function("cpu_handle_guest_debug")
        .allowlist_function("cpu_io_recompile")
        .allowlist_function("cpu_loop_exit_noexc")
        .allowlist_function("cpu_reset")
        .allowlist_function("cpu_stop_current")
        .allowlist_function("cpu_work_list_empty")
        .allowlist_function("cpus_register_accel")
        .allowlist_function("get_system_memory")
        .allowlist_function("hoedur_tcg_prologue_init")
        .allowlist_function("main_loop_wait")
        .allowlist_function("memory_region_add_subregion_overlap")
        .allowlist_function("memory_region_add_subregion")
        .allowlist_function("memory_region_get_ram_ptr")
        .allowlist_function("memory_region_init_((alias)|(io)|(ram(_ptr)?))")
        .allowlist_function("memory_region_reset_dirty")
        .allowlist_function("memory_region_set_dirty")
        .allowlist_function("memory_region_set_log")
        .allowlist_function("memory_region_set_readonly")
        .allowlist_function("memory_region_snapshot_and_clear_dirty")
        .allowlist_function("object_initialize_child_internal")
        .allowlist_function("object_property_set_link")
        .allowlist_function("page_init")
        .allowlist_function("process_queued_cpu_work")
        .allowlist_function("qdev_new")
        .allowlist_function("qdev_prop_set_string")
        .allowlist_function("qemu_cond_init")
        .allowlist_function("qemu_cpu_is_self")
        .allowlist_function("qemu_get_cpu")
        .allowlist_function("qemu_get_thread_id")
        .allowlist_function("qemu_guest_random_seed_thread_part2")
        .allowlist_function("qemu_init")
        .allowlist_function("qemu_reset_requested_get")
        .allowlist_function("qemu_shutdown_requested_get")
        .allowlist_function("qemu_system_reset_request")
        .allowlist_function("qemu_system_shutdown_request")
        .allowlist_function("qemu_target_page_size")
        .allowlist_function("qemu_thread_get_self")
        .allowlist_function("register_module_init")
        .allowlist_function("runstate_set")
        .allowlist_function("sysbus_realize_and_unref")
        .allowlist_function("sysbus_realize")
        .allowlist_function("tb_htable_init")
        .allowlist_function("tcg_cpu_init_cflags")
        .allowlist_function("tcg_init")
        .allowlist_function("tcg_region_init")
        .allowlist_function("tcg_register_thread")
        .allowlist_function("tcg_tb_lookup")
        .allowlist_function("tlb_flush")
        .allowlist_function("tlb_plugin_lookup")
        .allowlist_function("type_register_static")
        .allowlist_function("vm_state_notify")
        .allowlist_type("AccelClass")
        .allowlist_type("AccelOpsClass")
        .allowlist_type("CPUClass")
        .allowlist_type("DeviceClass")
        .allowlist_type("DirtyBitmapSnapshot")
        .allowlist_type("MachineClass")
        .allowlist_type("MachineState")
        .allowlist_type("MemOp(Idx)?")
        .allowlist_type("qemu_plugin_mem_rw")
        .allowlist_type("qemu_plugin_meminfo_t")
        .allowlist_type("TCGCPUOps")
        .allowlist_type("TCGHelperInfo")
        .allowlist_var("(((insn)|(tb))_((start)|(end)))_hook")
        .allowlist_var("((mem_access)|(tb_flush)|(rom_write))_hook")
        .allowlist_var("CF_[A-Z_]+")
        .allowlist_var("current_machine")
        .allowlist_var("dh_((callflag)|(typecode))_[0-9a-z]+")
        .allowlist_var("DIRTY_MEMORY_VGA")
        .allowlist_var("error_((abort)|(fatal))")
        .allowlist_var("EXCP_[A-Z_]+")
        .allowlist_var("GETPC_ADJ")
        .allowlist_var("NANOSECONDS_PER_SECOND")
        .allowlist_var("TARGET_INSN_START_WORDS")
        .allowlist_var("tcg_allowed")
        .allowlist_var("TCG_CALL_[A-Z_]+")
        .allowlist_var("TYPE_((ACCEL)|(ACCEL_OPS)|(MACHINE)|(SYS_BUS_DEVICE))")
        .blocklist_function("main_loop_wait") // bindgen issue #1313
        .parse_callbacks(Box::new(bindgen::CargoCallbacks));

    // arch specific functions
    let bindings = match arch {
        Arch::Arm => bindings
            .allowlist_function("arm_register_el_change_hook")
            .allowlist_function("armv7m_nvic_set_pending")
            .allowlist_function("clock_new")
            .allowlist_function("cpsr_read")
            .allowlist_function("nvic_(security_)?post_load")
            .allowlist_function("qdev_connect_clock_in")
            .allowlist_function("qdev_prop_set_uint32")
            .allowlist_type("arm_features")
            .allowlist_type("ARMCPU")
            .allowlist_type("ARMv7MState")
            .allowlist_type("NVICState")
            .allowlist_var("nvic_abort_hook"),
    };

    // generate + write bindings
    bindings.generate()
}