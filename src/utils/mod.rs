pub mod errors;

use std::{path::{PathBuf, Path}, error::Error, io::Read, fs::File};

use self::errors::GenericError;

pub fn load_file(buf: &mut Vec<u8>, path: &PathBuf) -> Result<usize, Box<dyn Error>> {
    let mut file = File::open(path)?;
    Ok(file.read_to_end(buf)?)
}

pub fn check_path(path: &str) -> Result<PathBuf, errors::GenericError> {
    let path = Path::new(path);
    if path.exists() {
        return Ok(path.to_path_buf());
    }
    Err(errors::GenericError::PathNotValid)
}

pub fn get_file_name_from_path(
    path: &PathBuf,
    forced_val: &Option<String>) 
-> Result<String, GenericError> {
    if forced_val.is_some(){
        return Ok(String::from(forced_val.clone().unwrap()));
    }
    Ok(String::from(path.file_name()
        .ok_or(errors::GenericError::UnableToGetDLLNameFromPath)?
        .to_str()
        .ok_or(errors::GenericError::UnableToGetDLLNameFromPath)?))

}
