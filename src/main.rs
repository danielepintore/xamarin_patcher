use std::process;

fn main() {
    if let Err(e) = xamarin_patcher::run() {
        eprintln!("Application error: {e}");
        process::exit(-1);   
    }
}


