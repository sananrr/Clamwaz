import os
import sys
import subprocess
from datetime import datetime
import socket

hostname = socket.gethostname()
ip_addr = socket.gethostbyname(hostname)

def clamav_scan(path):
    input_dir = "/var/log/clamav/script_log"

    if not path:
        print("Please provide a directory or file path for scanning. Example: python3 clamwaz.py <path>")
        return

    if not os.path.exists(path):
        print(f"Error: The specified path '{path}' does not exist.")
        return

    if not os.path.exists(input_dir):
        os.makedirs(input_dir)

    print("Clamscan is scanning...")

    # Run clamscan and capture the output
    clamscan_output = subprocess.run(["clamscan", "-i", path], capture_output=True, text=True)

    # Find the line number containing "FOUND" in clamscan output
    found_line = next((i for i, line in enumerate(clamscan_output.stdout.split('\n')) if "FOUND" in line), None)

    if found_line is not None:
        # Extract relevant log line
        log_line = clamscan_output.stdout.split('\n')[found_line].strip()

        # Format log line and append to clamav.log
        timestamp = datetime.now().strftime("[%a %b %d %H:%M:%S.%f %Y]")
        log = f"{timestamp} [clamav] [pid: 7] [client: {ip_addr}] {hostname} clamav_log: {log_line}"

        with open(os.path.join(input_dir, "clamav.log"), 'a') as output_file:
            output_file.write(log + "\n")

        print("Results of clamscan:", log)
    else:
        print("No malware found during the scan.")

if __name__ == "__main__":
    clamav_scan(sys.argv[1] if len(sys.argv) > 1 else None)
