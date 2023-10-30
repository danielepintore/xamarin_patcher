mod utils;

use std::{error::Error, path::PathBuf, fs::{File, self}, io::{Write, Read}};
use clap::{Parser, Subcommand};
use elf::{ElfBytes, endian::AnyEndian};
use flate2::{bufread::GzEncoder, Compression, read::GzDecoder};

use crate::utils::errors;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Extract {
        lib: String,
        output_dir: Option<String>,
    },
    Rebundle {
        lib: String,
        dll: String,
        dll_name: Option<String>,
    },
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Extract { lib, output_dir } => {extract(&lib, &output_dir)?}
        Commands::Rebundle { lib, dll, dll_name } => { rebundle(&lib, &dll, &dll_name)? }
    }
    Ok(())
}

fn extract(lib_path: &str, output_dir: &Option<String>) 
-> Result<(), Box<dyn Error>> {
    println!("Extracting dlls from the lib...");
    println!("Loading the lib...");
    let lib_path = utils::check_path(lib_path)?;
    let mut lib_raw: Vec<u8> = Vec::new();
    utils::load_file(&mut lib_raw, &lib_path)?;
    let lib = ElfBytes::<AnyEndian>::minimal_parse(lib_raw.as_slice())?;
    println!("Lib loaded");
    
    // get dymsym symbols table and dynsym string table
    let common_data = lib.find_common_data()?;
    let dynsyms = common_data.dynsyms
        .ok_or(errors::GenericError::NoDynSymTable)?;
    let strtab = common_data.dynsyms_strs
        .ok_or(errors::GenericError::NoDynStrTable)?;
    let hash_table = common_data.sysv_hash
        .ok_or(errors::GenericError::NoSysVHashTable)?;
    
    // Check if the lib provided is a mkbundle
    let (_sym_idx, sym) = hash_table.find(b"mono_mkbundle_init", &dynsyms, &strtab)?
        .ok_or(errors::GenericError::NotMonoMKBundle)?;
    if sym.is_undefined() {
        return Err(Box::new(errors::GenericError::NotMonoMKBundle));
    }

    // Create output dir
    let output_path = PathBuf::from(output_dir
                                    .clone()
                                    .unwrap_or_else(|| "./dll".to_string()));
    
    if output_path.exists() && output_path.read_dir()?.next().is_some() {
        return Err(Box::new(errors::GenericError::OutputPathNotEmpty));
    } else if !output_path.exists() {
        fs::create_dir(output_dir
                       .clone()
                       .unwrap_or_else(|| "./dll".to_string()))?;
    } 

    // Search dlls inside the lib
    //let mut dlls_syms: Vec<Symbol> = Vec::new();
    for sym in dynsyms.iter() {
        let sym_name = strtab.get(usize::try_from(sym.st_name)?)?;
        if sym_name.starts_with("assembly_data_") {
            //dlls_syms.push(sym);
            // Extract dll name
            let dll_name_len = sym_name.len() - 4;
            let dll_name = &sym_name[14..dll_name_len];
            // Extract dll
            let mut dll_path = PathBuf::from(output_dir
                                             .clone()
                                             .unwrap_or_else(|| "./dll".to_string()));
            dll_path.push(dll_name);
            dll_path.set_extension("dll");
            println!("Writing {}", dll_name);
            let mut file = File::create(&dll_path)?; 
            let start_pos: usize = usize::try_from(sym.st_value)?;
            let end_pos: usize = start_pos + usize::try_from(sym.st_size)?;

            let mut dll_uncompressed = Vec::new();
            let dll_compressed = &lib_raw[start_pos..end_pos];
            let mut gz = GzDecoder::new(dll_compressed);
            gz.read_to_end(&mut dll_uncompressed)?;
            file.write_all(&dll_uncompressed)?; 
        }
    }
    Ok(())
}

fn rebundle(
    lib_path: &str, 
    dll_path: &str, 
    dll_name: &Option<String>) 
-> Result<(), Box<dyn Error>> {
    println!("[Warning]: function not tested, you may get undefined behavior");
    println!("Loading the lib...");
    let lib_path = utils::check_path(lib_path)?;
    let mut lib_raw: Vec<u8> = Vec::new();
    utils::load_file(&mut lib_raw, &lib_path)?;
    let lib = ElfBytes::<AnyEndian>::minimal_parse(lib_raw.as_slice())?;
    println!("Lib loaded");
    
    // get dymsym symbols table and dynsym string table
    let common_data = lib.find_common_data()?;
    let dynsyms = common_data.dynsyms
        .ok_or(errors::GenericError::NoDynSymTable)?;
    let strtab = common_data.dynsyms_strs
        .ok_or(errors::GenericError::NoDynStrTable)?;
    let hash_table = common_data.sysv_hash
        .ok_or(errors::GenericError::NoSysVHashTable)?;
    
    // Check if the lib provided is a mkbundle
    let (_sym_idx, sym) = hash_table.find(b"mono_mkbundle_init", &dynsyms, &strtab)?
        .ok_or(errors::GenericError::NotMonoMKBundle)?;
    if sym.is_undefined() {
        return Err(Box::new(errors::GenericError::NotMonoMKBundle));
    }

    // get dll name from path
    let dll_path = PathBuf::from(dll_path);
    let replace_dll_name = utils::get_file_name_from_path(&dll_path, &dll_name)?;
    for sym in dynsyms.iter() {
        let sym_name = strtab.get(usize::try_from(sym.st_name)?)?;
        if sym_name.starts_with("assembly_data_") {
            // Extract dll name
            let dll_name_len = sym_name.len() - 4;
            let dll_name = &sym_name[14..dll_name_len];
            if dll_name.eq(&replace_dll_name) {
                println!("Replacing {}...", dll_name);
                let mut new_dll: Vec<u8> = Vec::new();
                utils::load_file(&mut new_dll, &dll_path)?;
                
                // compress dll with gzip before replacing
                let start_pos: usize = usize::try_from(sym.st_value)?;
                let end_pos: usize = start_pos + usize::try_from(sym.st_size)?; 
                let mut dll_compressed = Vec::new();
                let dll_old = &lib_raw[start_pos..end_pos];
                let mut gz = GzEncoder::new(dll_old, Compression::fast());
                gz.read_to_end(&mut dll_compressed)?;

                // Display some stats
                println!("Size stats:");
                println!("Old dll size: {}", dll_old.len());
                println!("New dll size: {}", dll_compressed.len());

                // Replace the compressed dll in the lib
                println!("Performing patching...");
                let pad = dll_old.len() - dll_compressed.len();
                if pad > 0 {
                    dll_compressed.resize(pad, 0);
                }
                let mut lib_patched_path = lib_path.clone();
                lib_patched_path.set_extension("so_patched");
                println!("{:?}", lib_patched_path);
                let mut file = File::create(&lib_patched_path)?;
                file.write_all(&lib_raw[..start_pos])?;
                file.write_all(&dll_compressed)?;
                file.write_all(&lib_raw[end_pos..])?;
                println!("Lib patched successfully!!");
            }
        }
    }
    Ok(())

}
