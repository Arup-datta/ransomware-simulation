import pyinotify
import psutil
import time
import os
from datetime import datetime
import threading
import hashlib
import subprocess
import math


DIRECTORIES_TO_MONITOR = ['/home/student/test']
# Threshold for file entropy to detect encryption
ENTROPY_THRESHOLD = 7.0

SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.aes']


file_hashes = {}


LOG_FILE = "ransomware_monitor.log"


#Store critical logs in a file
def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} - {message}\n")
    print(message)


#Calculate hash of a file
def calculate_file_hash(filepath):
    try:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        log_event(f"[ERROR] Could not hash file {filepath}: {e}")
        return None


class EventHandler(pyinotify.ProcessEvent):

    def process_IN_MODIFY(self, event):
        hash_before = file_hashes.get(event.pathname)
        hash_after = calculate_file_hash(event.pathname)

        if hash_before and hash_before != hash_after:
            log_event(f"[ALERT] File modified with possible encryption: {event.pathname}")
            self.check_file_encryption(event.pathname, "modified")	   
        else:
            log_event(f"[INFO] File modified: {event.pathname}")
        file_hashes[event.pathname] = hash_after

    def process_IN_CREATE(self, event):
        _, ext = os.path.splitext(event.pathname)
        if ext in SUSPICIOUS_EXTENSIONS:
            self.check_file_encryption(event.pathname, "created")
            log_event(f"[WARNING] Suspicious file created: {event.pathname}")
        else:
            log_event(f"[INFO] File created: {event.pathname}")

    def process_IN_DELETE(self, event):
        log_event(f"[WARNING] File deleted: {event.pathname}")
        file_hashes.pop(event.pathname, None)

    def check_file_encryption(self, file_path, action):
        if os.path.isfile(file_path):
            if is_file_encrypted(file_path):
                print(f"[ALERT] File {file_path} {action} and appears encrypted!")
                print("[ALERT] RANSOMWARE ATTACK!!!!!")
                

# Function to calculate file entropy
def calculate_entropy(file_path):
    print(file_path)
    try:
        with open(file_path, 'rb') as f:
            byte_counts = [0] * 256
            for byte in f.read():
                byte_counts[byte] += 1
            file_size = sum(byte_counts)
            if file_size == 0:
                return 0
            entropy = -sum(count / file_size * math.log2(count / file_size) for count in byte_counts if count > 0)
            return entropy
    except Exception as e:
        return None

def is_file_encrypted(file_path, threshold=ENTROPY_THRESHOLD):
    entropy = calculate_entropy(file_path)
    if entropy and entropy > threshold:
        return True
    return False


#Check sus keywords in terminal text
def monitor_processes(check_interval=1):
    while True:
        for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
            try:
                pid = process.info['pid']
                name = process.info['name']
                cmdline = ' '.join(process.info['cmdline']).lower()
                # Check for cryptographic tools or suspicious commands
                if any(keyword in cmdline for keyword in SUSPICIOUS_EXTENSIONS):
                    print(f"[ALERT] Suspicious process detected: {name} (PID: {pid}) using command: {cmdline}")

                # Detect processes handling many files
                open_files = process.open_files()
                if len(open_files) > 50:  #Threshold for bulk access
                    print(f"[CRITICAL] Process {name} (PID: {pid}) accessing {len(open_files)} files. Possible ransomware activity!")
                    print("[ALERT] POSSIBLE RANSOMWARE ATTACK!!!!!")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        time.sleep(check_interval)


#Calculate hashes every 5 seconds ~~
def monitor_file_hashes(check_interval=5):
    while True:
        for directory in DIRECTORIES_TO_MONITOR:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        current_hash = calculate_file_hash(filepath)
                        if filepath in file_hashes and file_hashes[filepath] != current_hash:
                            log_event(f"[ALERT] Unexpected file change detected: {filepath}")
                        file_hashes[filepath] = current_hash
        time.sleep(check_interval)


if __name__ == "__main__":
    wm = pyinotify.WatchManager()
    event_handler = EventHandler()
    notifier = pyinotify.Notifier(wm, event_handler)

    for directory in DIRECTORIES_TO_MONITOR:
        if os.path.exists(directory):
            wm.add_watch(directory, pyinotify.ALL_EVENTS, rec=True)
        else:
            log_event(f"[ERROR] Directory not found: {directory}")


    #Precompute hashes for all directories
    for directory in DIRECTORIES_TO_MONITOR:
        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                if os.path.isfile(filepath):
                    file_hashes[filepath] = calculate_file_hash(filepath)

    threading.Thread(target=monitor_processes, daemon=True).start()


    threading.Thread(target=monitor_file_hashes, daemon=True).start()


    log_event("[INFO] Monitoring started...")
    try:
        notifier.loop()
    except KeyboardInterrupt:
        log_event("[INFO] Stopping monitoring...")
        notifier.stop()
