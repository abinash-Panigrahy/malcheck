# malcheck
this is a malware analysis python tool ,you can scan a file by using this tool.
# 🛡️ MalScan - Malicious File Scanner

MalScan is a lightweight Python tool designed to help defenders scan directories for potentially malicious files based on:
- File hash matching
- Suspicious file extensions
- Detection of suspicious strings in file content

It is intended for use in **blue teaming** operations or basic malware triage.

---

## 📦 Features
- Scan files recursively in a given directory
- Flag files based on:
  - Known malicious hashes
  - Suspicious file extensions (.bat, .exe, .ps1, .dll, etc.)
  - Suspicious keywords (e.g., `powershell`, `cmd.exe`, `wget`)
- Generate a scan report (`malscan_report.json`)

---

## 🚀 Usage Instructions

### 🔹 Requirements
- Python 3.x
- Works on **Windows** and **Linux** (e.g., Kali Linux)

---

### 🔹 How to Run on **Windows**:

1. Open **PowerShell** or **Command Prompt**.
2. Navigate to the folder containing `malscan.py`.
   ```powershell
   cd "C:\path\to\your\malscan\folder"
