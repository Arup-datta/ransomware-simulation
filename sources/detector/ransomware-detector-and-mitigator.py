import pyinotify
import psutil
import time
import os
from datetime import datetime
import threading
import hashlib
import subprocess
import math
import notify2
import shutil
from collections import Counter
import os

DIRECTORIES_TO_MONITOR = ['/home/student/test']
# Threshold for file entropy to detect encryption
ENTROPY_THRESHOLD = 6.0

backup_dir = '/home/student/backup'
monitored_dir = '/home/student/test'

SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.aes']

is_attacked = False

file_hashes = {}


LOG_FILE = "/home/student/ransomware_monitor.log"
MITIGATION_LOG_FILE = "/home/student/mitigation.log"

#Store critical logs in a file
def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} - {message}\n")
    print(message)




# Rollback files from backup --- update code later
def rollback_files():
    global is_attacked
    if is_attacked == False:
      return
    print("[INFO] =========>>>>>>>>>> Rolling back files from backup after 30 seconds <<<<<<<<<=========")
    time.sleep(30)
    try:
      if os.path.exists(backup_dir):
        for root, _, files in os.walk(backup_dir):
          for file in files:
            src_path = os.path.join(root, file)
            dest_path = monitored_dir
            shutil.copy2(src_path, dest_path)
            log_event(f"Restored file: {dest_path}")
      else:
        log_event(f"No backup found for directory: {directory}")
      print("[INFO] ============>>>>>>>> Backup complete <<<<<<<============")
    except Exception as e:
        log_event(f"Error during rollback: {e}")
    is_attacked = False



# Terminate ransomware processes
def terminate_ransomware_processes():
    suspicious_keywords = ['.aes', 'ransomware', 'encrypt']
    current_pid = os.getpid()
    for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        if process.info['pid'] == current_pid:
          continue
        cmdline = process.info['cmdline']
        try:
            if cmdline:
              cmdline = ' '.join(process.info['cmdline']).lower()
              if any(keyword in cmdline for keyword in suspicious_keywords):
                if process.info['pid'] == current_pid:
                  continue
                log_event(f"Terminating process: {process.info['name']} (PID: {process.info['pid']})")
                process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

# Isolate the infected system
def isolate_system():
    try:
        os.system("sudo ifconfig eth0 down")
        log_event("Network interface disabled to isolate system.")
    except Exception as e:
        log_event(f"Error isolating system: {e}")


# Monitor and mitigate ransomware activity
def monitor_and_mitigate():
    log_event("[INFO] Starting ransomware mitigation system...")
    while True:
        try:
            terminate_ransomware_processes()
            rollback_files()
        except KeyboardInterrupt:
            log_event("[INFO] Stopping mitigation system...")
            break


def backup_files():
    global is_attacked
    backup_interval = 5 #backup every 5 seconds
    print("System will backup the directory after 5 seconds")
    time.sleep(backup_interval)
    print("BACKUP FLAG " + str(is_attacked))
    while True:
      if is_attacked == True:
        time.sleep(backup_interval)
        continue
      print("[INFO]  =======>>>>>>> UPDATING BACKUP OF THE DIRECTORY <<<<<<<======== ")
      try:
        if os.path.exists(monitored_dir):
          for root, _, files in os.walk(monitored_dir):
            for file in files:
              src_path = os.path.join(root, file)
              dest_path = backup_dir
              print(src_path)
              print(dest_path)
              shutil.copy2(src_path, dest_path)
              log_event(f"Backup file: {dest_path}")
        else:
          log_event(f"[ERROR] No dir found for backup")
      except Exception as e:
        log_event(f"[ERROR] Error during backup: {e}")
      time.sleep(backup_interval)



# Set up the notification system (Ubuntu)
def setup_notifications():
    notify2.init("Log Monitor")
    return notify2.Notification

# Function to show a desktop notification
def show_notification(message):
    notification = notify2.Notification("Log Alert", message)
    notification.set_timeout(10000)  # Show for 10 seconds
    notification.show()


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
            global is_attacked
            print(f"[ALERT] File {file_path} {action} and appears encrypted!")
            print("[ALERT] RANSOMWARE ATTACK!!!!!")
            show_notification("Ransomware Attack")
            is_attacked = True
            print("Stopping Backup - Ransomware Attack")
            monitor_and_mitigate()

# Function to calculate file entropy
def is_file_encrypted(file_path, entropy_threshold=7.5, block_size=16):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            print("File is empty, cannot determine encryption.")
            return False

        # Step 1: Calculate entropy
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = -sum((count / total_bytes) * math.log2(count / total_bytes)
                       for count in byte_counts.values())

        # Step 2: Check uniform byte distribution
        byte_frequencies = [count / total_bytes for count in byte_counts.values()]
        max_deviation = max(abs(freq - 1/256) for freq in byte_frequencies)  # Ideal random is ~1/256

        # Step 3: Check AES block alignment
        is_block_aligned = total_bytes % block_size == 0
        print("Entropy value " + str(entropy))
        print(max_deviation)
        print(is_block_aligned)
        # Determine if the file is likely encrypted
        if entropy > entropy_threshold and max_deviation < 0.01 and is_block_aligned:
            return True

        return False
    except Exception as e:
        print(f"Error reading the file: {e}")
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
                if len(open_files) > 70:  #Threshold for bulk access
                    print(f"[CRITICAL] Process {name} (PID: {pid}) accessing {len(open_files)} files. Possible ransomware activity!")
                    print("[ALERT] POSSIBLE RANSOMWARE ATTACK!!!!!")
                    show_notification("Too many files got modified. Possible ransomware attack")
                    is_attacked = True
                    rollback_files()
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
    notification = setup_notifications() #Setting up UI notifications

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


    threading.Thread(target=backup_files, daemon=True).start()

    log_event("[INFO] Monitoring started...")
    try:
        notifier.loop()
    except KeyboardInterrupt:
        log_event("[INFO] Stopping monitoring...")
        notifier.stop()
