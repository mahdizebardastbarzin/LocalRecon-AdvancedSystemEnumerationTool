# 🚀 LocalRecon – Advanced System Enumeration Tool | ابزار پیشرفته شناسایی سیستم


![LocalRecon – Advanced System Enumeration Tool](https://github.com/mahdizebardastbarzin/LocalRecon-AdvancedSystemEnumerationTool/blob/main/LocalRecon.png)

---

## 📌 Program Overview | معرفی برنامه

**LocalRecon** is a comprehensive **System Enumeration & Reconnaissance Tool** designed for **educational, defensive security, and ethical penetration testing** purposes.
این برنامه یک ابزار جامع **شناسایی و جمع‌آوری اطلاعات سیستم** است که برای **آموزش، امنیت دفاعی و تست نفوذ اخلاقی** طراحی شده است.

The tool works in **two modes**:

* **CLI (Non‑Graphical / Command Line)**
* **GUI (Graphical User Interface)**

LocalRecon operates in a **read‑only and safe manner**, meaning it does **not modify the system**.
این ابزار به صورت **فقط‌خواندنی و امن** عمل می‌کند و هیچ تغییری در سیستم ایجاد نمی‌کند.

---

## 🧠 What Does LocalRecon Do? | LocalRecon چه کاری انجام می‌دهد؟

LocalRecon gathers, analyzes, and organizes **low‑level and high‑level system information** to help security professionals **understand the target environment** before making security decisions.
LocalRecon اطلاعات سطح پایین و سطح بالای سیستم را جمع‌آوری و دسته‌بندی می‌کند تا متخصص امنیت بتواند **محیط هدف را به‌درستی تحلیل کند**.

In cybersecurity, tools like this are known as:

* **System Reconnaissance Tools**
* **Local Enumeration Tools**
* **Host Information Gathering Utilities**

---

## 🧩 Capabilities | قابلیت‌ها (بیش از ۳۰ عملکرد)

1. Operating System details (name, version, architecture)
2. Kernel information and uptime
3. CPU model, cores, and usage
4. Memory (RAM) total, used, free
5. Swap memory status
6. Disk partitions and usage
7. Mounted filesystems
8. Current user information
9. Logged‑in users
10. User privileges and permissions
11. Environment variables (limited)
12. Hostname and FQDN
13. Local IP addresses
14. Network interfaces
15. Active network connections
16. Running processes
17. System services
18. Scheduled tasks / cron jobs
19. Installed applications
20. Installed browsers
21. Antivirus detection
22. Firewall and security features
23. SELinux / AppArmor / UAC status
24. Virtualization detection (VM / Docker)
25. Cloud environment detection
26. Kernel modules (Linux)
27. Read/Write/Execute permission checks
28. JSON report generation
29. Timestamped output
30. Append or overwrite output files
31. Custom output directory
32. GUI‑based result visualization

---

## 📚 Libraries Used | کتابخانه‌های استفاده‌شده

* **os, sys, platform, socket, getpass, shutil, subprocess, time, datetime**
  Core system interaction

* **json**
  Structured output and reporting

* **psutil**
  Process, memory, disk, network, users

* **colorama**
  Colored CLI output

* **tkinter / ttk / scrolledtext**
  Graphical User Interface (GUI)

* **winreg** (Windows only)
  Registry inspection

---

## ⚙️ Installation & Requirements | نصب و پیش‌نیازها

### Requirements | پیش‌نیازها

* Python 3.10+
* Windows / Linux / macOS

### Install Dependencies | نصب کتابخانه‌ها

```bash
pip install psutil colorama
```

Tkinter is usually included with Python by default.

---

## ▶️ CLI Usage (Non‑Graphical Mode) | نحوه استفاده غیر گرافیکی

### CLS | محیط غیر گرافیکی

```bash
python localrecon.py --cli
```

### Quick Scan | اسکن سریع

```bash
python localrecon.py --quick
```

### Deep Scan | اسکن عمیق

```bash
python localrecon.py --deep
```

### Full Scan with JSON Output | اسکن کامل با خروجی JSON

```bash
python localrecon.py --full --json --timestamp --save-dir ./results
```

### Select Specific Modules | انتخاب ماژول‌ها

```bash
python localrecon.py --system --network --user --processes --env
```

CLI mode is suitable for **servers, headless systems, automation, and scripting**.

---

## 🖥️ GUI Usage (Graphical Mode) | نحوه استفاده گرافیکی

```bash
python localrecon.py
```

### GUI Features

* Scan mode selection (Quick / Deep / Full)
* Module selection (checkbox‑based)
* Output format selection (JSON / Text)
* Save directory chooser
* Scrollable result viewer
* Dark themed interface

GUI mode is ideal for **training, demonstrations, and desktop analysis**.

---

## 🛡️ Security Context | کاربرد در امنیت سایبری

LocalRecon is commonly used in:

* Defensive security audits
* Blue‑Team operations
* Red‑Team local enumeration phase
* Cybersecurity training labs
* Incident response preparation

This tool helps analysts **see the system the way an attacker would — before the attacker does**.

---

## ⚠️ Security Notice | هشدار امنیتی

This tool is intended **only for educational and defensive purposes**.
Running it on systems without permission may be illegal.

استفاده از این ابزار فقط برای **آموزش و امنیت دفاعی** مجاز است و اجرای آن بدون مجوز می‌تواند غیرقانونی باشد.

---

## ✅ Summary | جمع‌بندی

LocalRecon provides **clear visibility into system internals** through both **CLI and GUI**, helping users understand security posture safely and professionally.
LocalRecon دیدی شفاف و حرفه‌ای از وضعیت سیستم ارائه می‌دهد و ابزار مناسبی برای آموزش و تحلیل امنیتی است.

---

© Educational / Defensive Security Tool




