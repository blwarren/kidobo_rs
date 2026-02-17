use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Read the entire file into a `String`, but cap how many bytes are read.
pub fn read_to_string_with_limit(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file).take(max_bytes as u64);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Read the entire file into a byte vector, while capping how many bytes are read.
pub fn read_bytes_with_limit(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file).take(max_bytes as u64);
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents)?;
    Ok(contents)
}
