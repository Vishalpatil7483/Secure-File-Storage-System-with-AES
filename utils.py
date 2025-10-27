"""
utils.py - small helpers for logging, safe filenames, and progress
"""

import os
from datetime import datetime

ACTIVITY_LOG = "activity_log.txt"
META_LOG = "metadata_log.txt"

def ensure_dirs():
    if not os.path.exists("vault_keys"):
        os.makedirs("vault_keys")
    if not os.path.exists("encrypted"):
        os.makedirs("encrypted")
    if not os.path.exists("decrypted"):
        os.makedirs("decrypted")

def log_activity(action: str, filename: str):
    with open(ACTIVITY_LOG, "a") as fw:
        fw.write(f"{datetime.now()} - {action} - {filename}\n")

def log_metadata(action: str, filename: str, filesize: int):
    with open(META_LOG, "a") as fw:
        fw.write(f"{datetime.now()} | {action} | {filename} | {filesize} bytes\n")

def safe_output_name(inp: str):
    base = os.path.basename(inp)
    return base
