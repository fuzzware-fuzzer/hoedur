use anyhow::Result;
use rune::Module;

/**
 * @Article Script Functions
 * ## Common ARM instructions
 *
 * - `arm::NOP`         // nop
 * - `arm::WFI`         // wfi
 * - `arm::WFI_RETURN`  // wfi; bx lr
 * - `arm::RETURN`      // bx lr
 * - `arm::RETURN_0`    // mov r0, 0; bx lr
 * - `arm::RETURN_1`    // mov r0, 1; bx lr
 *
 * Example:
 * ```rune
 * common::patch(0xdead_beef, arm::RETURN);
 * ```
 */
pub fn module() -> Result<Module> {
    let mut module = Module::with_crate("arm");

    // ARM
    module.constant(["NOP"], vec![0x00, 0xbf])?; // nop
    module.constant(["WFI"], vec![0x30, 0xbf])?; // wfi
    module.constant(["WFI_RETURN"], vec![0x30, 0xbf, 0x70, 0x47])?; // wfi; bx lr
    module.constant(["RETURN"], vec![0x70, 0x47])?; // bx lr
    module.constant(["RETURN_0"], vec![0x4f, 0xf0, 0x00, 0x00, 0x70, 0x47])?; // mov r0, 0; bx lr
    module.constant(["RETURN_1"], vec![0x4f, 0xf0, 0x01, 0x00, 0x70, 0x47])?; // mov r0, 1; bx lr

    Ok(module)
}
