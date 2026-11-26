#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = bypax_core::updater::maybe_run_updater_helper(&args) {
        std::process::exit(code);
    }
    bypax_lib::run();
}
