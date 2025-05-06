# rustfim

A rust file integrity monitoring tool that watches a specific directory and logs to a file.

## Features
- Detects and logs file modifications, deletions and additions
- Simple config file to edit a few options

## Configuration file
Settings in the tool can be changed using the config.json. Ignored extensions can be left blank with an empty list.
```json
{
  "log_path": "./events.log",
  "scan_path": "test_dir",
  "scan_interval_secs": 1,
  "ignored_extensions": ["txt", "rs"]
}
```
