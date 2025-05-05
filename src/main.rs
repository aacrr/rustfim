use sha2::{Sha384, Digest};
use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::{thread, time};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use serde::Serialize;
use chrono;

#[derive(serde::Deserialize)]
struct Config {
    log_path: String,
    scan_path: String,
    scan_interval_secs: u64
}


#[derive(Serialize)]
struct LogEntry {
    timestamp: String,
    event: String, // Event type
    file_path: String,
    old_hash: String,
    new_hash: String
}

fn load_config(path: &Path) -> Option<Config>{ // Either returns config or None
    match File::open(path) {
        Ok(mut file) => {
            let mut contents: String = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => match serde_json::from_str(&contents) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        eprintln!("Failed to parse config into JSON: {:?}", e);
                        None
                    }
                }, Err(e) => {
                    eprintln!("Failed to read config file: {:?}", e);
                    None
                }
            }
        } Err(e) => {
            eprintln!("Failed to open config file: {:?}", e);
            None
        }
    }
}

fn add_to_log(log_path: &Path, entry: &LogEntry) {
    match OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path) {
            Ok(mut log_file) => {
                if let Ok(json) = serde_json::to_string(entry) {
                    if let Err(e) = writeln!(log_file, "{}", json) {
                        eprintln!("Error writing to log file: {:?}", e)
                    }
                } else {
                    eprintln!("Failed to serialise log entry.")
                }
            }
            Err(e) => {
                eprintln!("Failed to open log file: {:?}", e)
            }
        }
}

fn hash_file(path: &PathBuf) -> String{
    let bytes: Vec<u8> = fs::read(path).unwrap(); //Vec<u8>
    let hash = Sha384::digest(&bytes);
    hex::encode(hash)
}   

fn get_file_hashes(scan_path: &Path) -> HashMap<PathBuf, String>{
    let mut hash_map: HashMap<PathBuf, String> = HashMap::new();
    if scan_path.is_dir() { // Check if path is valid first
        for entry in fs::read_dir(scan_path).unwrap(){
            let path: PathBuf = entry.unwrap().path();
            if path.is_file() {
                let hash: String= hash_file(&path);
                hash_map.insert(path, hash);
            }
        }
    } else {
        eprintln!("Path not a directory")
    }
    hash_map

}

fn main() {
    // Using config file

    let config = match load_config(Path::new("./config.json")) {
        Some (conf) => conf,
        None => {
            eprintln!("Unable to load the config file.");
            return;
        }
    };

    let log_path: &Path = Path::new(&config.log_path);
    let scan_path: &Path = Path::new(&config.scan_path);
    let interval: u64 = config.scan_interval_secs;
    
    // Initial scan 
    let mut old_hash_map: HashMap<PathBuf, String>  = get_file_hashes(scan_path);
    let mut last_hash_map: HashMap<PathBuf, String> = old_hash_map.clone();

    loop {
        thread::sleep(time::Duration::from_secs(interval));

        let new_hash_map: HashMap<PathBuf, String> = get_file_hashes(scan_path);
        for (path, new_hash) in new_hash_map.iter() {
            match old_hash_map.get(path) {
                Some(old_hash) => {
                    if old_hash.as_str() != new_hash {
                        let last_hash: Option<&String> = last_hash_map.get(path);
                        if last_hash != Some(&new_hash) {
                            let log_entry = LogEntry {
                                timestamp: chrono::offset::Utc::now().to_rfc3339(),
                                event: "modified".to_string(),
                                file_path: path.display().to_string(),
                                old_hash: old_hash.to_string(),
                                new_hash: new_hash.to_string()
                            };
                            add_to_log(log_path, &log_entry);
                            last_hash_map.insert(path.to_path_buf(), new_hash.to_string());
                        }
                        
                    }
                }
                None => {
                    let log_entry: LogEntry = LogEntry {
                        timestamp: chrono::offset::Utc::now().to_rfc3339(),
                        event: "added".to_string(),
                        file_path: path.display().to_string(),
                        old_hash: "".to_string(),
                        new_hash: new_hash.to_string()
                    };
                    add_to_log(log_path, &log_entry);
                    last_hash_map.insert(path.to_path_buf(), new_hash.to_string());
                }
            }
        }

        for old_path in old_hash_map.keys() {
            if !new_hash_map.contains_key(old_path) {
                    let log_entry: LogEntry = LogEntry {
                        timestamp: chrono::offset::Utc::now().to_rfc3339(),
                        event: "deleted".to_string(),
                        file_path: old_path.display().to_string(),
                        old_hash: old_hash_map.get(old_path).unwrap().to_string(),
                        new_hash: "".to_string()
                    };
                    add_to_log(log_path, &log_entry);
                    last_hash_map.insert(old_path.to_path_buf(), "Deleted".to_owned());
            }
        }
        old_hash_map = new_hash_map;
    }
}