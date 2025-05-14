use sha2::{Sha384, Digest};
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use std::{thread, time};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use serde::Serialize;

#[derive(serde::Deserialize)]
struct Config {
    log_path: String,
    scan_path: String,
    scan_interval_secs: u64,

    #[serde(default)]
    ignored_extensions: HashSet<String>
}

#[derive(Serialize)]
struct LogEntry {
    timestamp: String,
    event: String, // Event type
    file_path: String,
    file_size: String,
    is_archive: bool,
    is_hidden: bool,
    is_read_only: bool,
    old_hash: String,
    new_hash: String
}

#[derive(Debug, Clone)]
struct FileInfo {
    hash: String,
    size: String,
    is_archive: bool,
    is_hidden: bool,
    is_read_only: bool,
}

fn load_config(path: &Path) -> Option<Config>{
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
                if let Ok(json) = serde_json::to_string_pretty(entry) {
                    if let Err(e) = writeln!(log_file, "{}", json) {
                        eprintln!("Error writing to log file: {:?}", e)
                    }
                } else {
                    eprintln!("Failed to serialise log entry.")
                }
            },
            Err(e) => {
                eprintln!("Failed to open log file: {:?}", e)
            }
        }
}

fn hash_file(path: &PathBuf) -> Option<String>{
    match fs::read(path) {
        Ok(bytes) => {
            let hash = Sha384::digest(&bytes);
            Some(hex::encode(hash))
        }, 
        Err(e) => {
            eprintln!("Failed to read file to hash: {:?} | {:?}", path, e);
            None
        }
    }
}   

fn human_readable_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size: f64 = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1000.0 && unit_idx < UNITS.len() - 1 {
        size /= 1000.0;
        unit_idx += 1;
    }
    format!("{:.1} {}", size, UNITS[unit_idx])
}

fn get_file_hashes(scan_path: &Path, ignored_ext: &HashSet<String>) -> HashMap<PathBuf, FileInfo>{
    let mut hash_map: HashMap<PathBuf, FileInfo> = HashMap::new();

    if !scan_path.is_dir() {
        eprintln!("Path is not a directory");
        return hash_map;
    }

    for entry in fs::read_dir(scan_path).unwrap() {
        let path = match entry {
            Ok(p) => p.path(),
            Err(e) => {
                eprintln!("{:?}",e);
                continue;
            }
        };

        if !path.is_file() {
            continue
        }

        if let Some(ext) = path.extension().and_then(|p| p.to_str()) {
            if ignored_ext.contains(ext) {
                continue;
            }
        }

        if let Some(hash) = hash_file(&path) {
            let mut is_archive = false;
            let mut is_hidden  = false;
            let mut is_read_only = false;
            let mut file_size = String::from("");

            match path.metadata() {
                Ok(meta) => {
                    let file_perms = meta.file_attributes();
                    is_archive = file_perms & 0x20 != 0;
                    is_hidden = file_perms & 0x02 != 0;
                    is_read_only = file_perms & 0x01 != 0;

                    let byte_size = meta.file_size();
                    file_size = human_readable_size(byte_size)

                }, Err(e) => {
                    eprintln!("Failed to get metadata: {:?} | {:?}", path, e);
                }
            }
            hash_map.insert(path, FileInfo {
                hash,
                size: file_size, 
                is_archive, 
                is_hidden, 
                is_read_only 
            });
        }
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
    let ignored_ext: HashSet<String> = config.ignored_extensions;
    
    // Initial scan 
    let mut old_hash_map: HashMap<PathBuf, FileInfo>  = get_file_hashes(scan_path, &ignored_ext);
    let mut last_hash_map: HashMap<PathBuf, FileInfo> = old_hash_map.clone();

    loop {
        thread::sleep(time::Duration::from_secs(interval));
        let new_hash_map: HashMap<PathBuf, FileInfo> = get_file_hashes(scan_path, &ignored_ext);

        for (path, new_info) in new_hash_map.iter() {
            match old_hash_map.get(path) {
                Some(old_info) => {
                    if old_info.hash != new_info.hash {
                        let last_info = last_hash_map.get(path);
                        if last_info.is_none_or(|last| last.hash != new_info.hash) {
                            let log_entry = LogEntry {
                                timestamp: chrono::offset::Utc::now().to_rfc3339(),
                                event: "modified".to_string(),
                                file_path: path.display().to_string(),
                                file_size: new_info.size.to_string(),
                                is_archive: new_info.is_archive,
                                is_hidden: new_info.is_hidden,
                                is_read_only: new_info.is_read_only,
                                old_hash: old_info.hash.to_string(),
                                new_hash: new_info.hash.to_string()
                            };
                            add_to_log(log_path, &log_entry);
                            last_hash_map.insert(path.to_path_buf(), new_info.to_owned());

                        }
                    }
                }
                None => {
                    let log_entry: LogEntry = LogEntry {
                        timestamp: chrono::offset::Utc::now().to_rfc3339(),
                        event: "added".to_string(),
                        file_path: path.display().to_string(),
                        file_size: new_info.size.to_string(),
                        is_archive: new_info.is_archive,
                        is_hidden: new_info.is_hidden,
                        is_read_only: new_info.is_read_only,
                        old_hash: "".to_string(),
                        new_hash: new_info.hash.to_string()
                    };
                    add_to_log(log_path, &log_entry);
                    last_hash_map.insert(path.to_path_buf(), new_info.to_owned());
                }
            }
        }

        for (old_path, old_info) in old_hash_map.iter() {
            if !new_hash_map.contains_key(old_path) {
                    let log_entry: LogEntry = LogEntry {
                        timestamp: chrono::offset::Utc::now().to_rfc3339(),
                        event: "deleted".to_string(),
                        file_path: old_path.display().to_string(),
                        file_size: old_info.size.to_string(),
                        is_archive: old_info.is_archive,
                        is_hidden: old_info.is_hidden,
                        is_read_only: old_info.is_read_only,
                        old_hash: old_info.hash.clone(),
                        new_hash: "".to_string()
                    };
                    add_to_log(log_path, &log_entry);
                    last_hash_map.remove(old_path);
            }
        }
        old_hash_map = new_hash_map;
    }
}
