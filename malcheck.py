import os
import hashlib
import json

# Example known malicious hashes (normally you would pull from a feed)
MALICIOUS_HASHES = [
    "5d41402abc4b2a76b9719d911017c592",  # example MD5
]

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.ps1', '.scr', '.dll']

# Suspicious keywords in files
SUSPICIOUS_KEYWORDS = ['powershell', 'cmd.exe', 'wget', 'curl', 'Invoke-Mimikatz']

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None
    return hash_md5.hexdigest()

def scan_file(file_path):
    alerts = []
    file_hash = calculate_md5(file_path)
    if not file_hash:
        return None

    # Check hash
    if file_hash in MALICIOUS_HASHES:
        alerts.append("Known malicious hash detected.")

    # Check extension
    _, ext = os.path.splitext(file_path)
    if ext.lower() in SUSPICIOUS_EXTENSIONS:
        alerts.append(f"Suspicious extension: {ext}")

    # Check content for suspicious keywords
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in content.lower():
                    alerts.append(f"Suspicious keyword found: {keyword}")
    except Exception:
        pass  # Binary files may cause read errors

    return {
        'file_path': file_path,
        'file_hash': file_hash,
        'alerts': alerts
    }

def scan_directory(directory_path):
    results = []
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            result = scan_file(file_path)
            if result and result['alerts']:
                results.append(result)
    return results

def main():
    directory = input("Enter directory path to scan: ")
    if not os.path.isdir(directory):
        print("Invalid directory.")
        return

    print(f"Scanning directory: {directory}...")
    scan_results = scan_directory(directory)

    # Save results
    report_path = "malscan_report.json"
    with open(report_path, "w") as report_file:
        json.dump(scan_results, report_file, indent=4)

    print(f"Scan complete. Report saved to {report_path}.")

if __name__ == "__main__":
    main()
