````markdown
# ReconForge 🔥

ReconForge is an advanced reconnaissance and enumeration framework built in Python for penetration testing and security analysis.

---

## 🚀 Features

- DNS Enumeration (A, MX, NS)
- Subdomain Discovery (Wordlist-based)
- Port Scanning (Fast & Full via Nmap)
- Service & Version Detection
- Directory Enumeration (with Tech Detection & Header Analysis)
- Risk Analysis Engine (HIGH / MEDIUM / LOW)
- Colorized CLI Output 🎨
- Multi-threaded Scanning ⚡
- Report Generation (TXT with timestamp)

---

## 🧠 Tech Stack

- Python 3.12
- python-nmap
- requests
- tqdm
- colorama

---

## ⚙️ Installation

```bash
git clone https://github.com/cyberjbx07/ReconForge.git
cd ReconForge

🪟 Windows Setup
# Create virtual environment
py -3.12 -m venv venv

# Activate venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt


🐧 Linux / macOS Setup
# Create virtual environment
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt



📦 Install Nmap (Required)

ReconForge uses Nmap for port scanning. Install it before running:

Windows:
Download from: https://nmap.org/download.html

Linux (Debian/Ubuntu):
sudo apt update
sudo apt install nmap

macOS (Homebrew):
brew install nmap
````

---

## ▶️ Usage

```bash
python main.py
```

---

## 🖥️ Sample Output

```
[INFO]========== PORT SCAN ==========

[OPEN] 22 → ssh → HIGH
[OPEN] 80 → http → MEDIUM
[OPEN] 443 → https → MEDIUM

--------------------------------------------------

[FOUND] /admin → 200
[FOUND] /login → 200

[WARNING] No subdomains found
```

---

## 📄 Reports

* Reports are automatically saved in the `output/` directory
* Each scan generates a unique file using timestamp

```
output/
 └── example_com/
      ├── 20260331_173012.txt
```

---

## 📁 Project Structure

```
ReconForge/
 ├── core/
 ├── engine/
 ├── utils/
 │    └── colors.py
 ├── data/
 ├── output/
 ├── main.py
 ├── requirements.txt
 └── README.md
```

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do not use it against targets without proper permission.

---

## 👤 Author

**CyberJBX (JBX07)**
GitHub: [https://github.com/cyberjbx07](https://github.com/cyberjbx07)

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!

```


