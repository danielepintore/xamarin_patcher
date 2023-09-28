use std::process;

fn main() {
    if let Err(e) = xamarin_bundle_tools::run() {
        eprintln!("Application error: {e}");
        process::exit(-1);   
    }
}


