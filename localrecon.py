#!/usr/bin/env python3

"""
LocalRecon
Advanced CLI-Based System Enumeration Tool
Educational / Defensive Security Use
"""

import os
import sys
import json
import argparse
import platform
import socket
import getpass
import shutil
import time
import subprocess
from datetime import datetime
import colorama
try:
    import psutil
except ImportError:
    psutil = None
try:
    import winreg
except ImportError:
    winreg = None

colorama.just_fix_windows_console()

# ==============================
# GLOBAL STATE
# ==============================
RESULTS = {}
OS_TYPE = platform.system()

# ==============================
# ANSI COLORS (DISPLAY ONLY)
# ==============================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    GRAY = "\033[90m"

# ==============================
# UTILITIES
# ==============================

def banner():
    print("=" * 80)
    print(" LocalRecon | Comprehensive System Enumeration Tool")
    print(" Read-Only | Educational & Defensive Security")
    print(" Powered by | Engineer Mahdi Zebardast Barzin")
    print(" github | https://github.com/mahdizebardastbarzin")
    print("=" * 80)


def now_ts():
    return datetime.utcnow().isoformat() + "Z"


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def log(section, key, value):
    if section not in RESULTS:
        RESULTS[section] = {}
    RESULTS[section][key] = value


def color_print_json(text):
    for line in text.splitlines():
        if '"' in line and ':' in line:
            key, val = line.split(':', 1)
            print(f"{C.CYAN}{key}:{C.RESET}{C.GREEN}{val}{C.RESET}")
        else:
            print(f"{C.GRAY}{line}{C.RESET}")


def plain_print_json(text):
    print(text)


def run_command(cmd):
    if isinstance(cmd, list):
        return subprocess.run(cmd, capture_output=True, text=True)
    else:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# ==============================
# ENUMERATION MODULES
# ==============================


def enum_system():
    log("system", "os", OS_TYPE)
    log("system", "release", platform.release())
    log("system", "version", platform.version())
    log("system", "platform", platform.platform())
    log("system", "architecture", platform.machine())
    log("system", "processor", platform.processor())
    log("system", "python", platform.python_version())

def enum_network():
    hostname = socket.gethostname()
    log("network", "hostname", hostname)
    try:
        log("network", "fqdn", socket.getfqdn())
    except:
        pass
    try:
        log("network", "primary_ip", socket.gethostbyname(hostname))
    except:
        pass
    if psutil:
        log("network", "interfaces", {k: [a.address for a in v] for k, v in psutil.net_if_addrs().items()})
        connections = psutil.net_connections()
        log("network", "open_connections_count", len(connections))
        log("network", "open_connections", [{"pid": c.pid, "laddr": c.laddr, "raddr": c.raddr, "status": c.status} for c in connections])

def enum_user():
    log("user", "username", getpass.getuser())
    log("user", "home", os.path.expanduser("~"))
    log("user", "cwd", os.getcwd())
    log("user", "shell", os.environ.get("SHELL"))

def enum_resources():
    log("resources", "cpu_cores", os.cpu_count())
    total, used, free = shutil.disk_usage(os.getcwd())
    log("resources", "disk_total_gb", round(total / (1024 ** 3), 2))
    log("resources", "disk_used_gb", round(used / (1024 ** 3), 2))
    log("resources", "disk_free_gb", round(free / (1024 ** 3), 2))

def enum_env():
    for k in ["PATH", "HOME", "USER", "USERNAME", "SHELL", "LANG", "TERM"]:
        if k in os.environ:
            log("environment", k, os.environ[k])

def enum_virtualization():
    indicators = []
    if OS_TYPE == 'Linux':
        checks = ["/.dockerenv", "/proc/vz", "/proc/xen", "/proc/scsi/scsi", "/proc/1/cgroup"]
        for i in checks:
            if os.path.exists(i):
                indicators.append(i)
        try:
            with open('/proc/cpuinfo') as f:
                if 'hypervisor' in f.read():
                    indicators.append('hypervisor flag')
        except:
            pass
        try:
            with open('/proc/1/cgroup') as f:
                if 'docker' in f.read() or 'kubepods' in f.read():
                    indicators.append('container')
        except:
            pass
    elif OS_TYPE == 'Windows':
        try:
            result = run_command('systeminfo')
            out = result.stdout
            if 'Virtual' in out or 'VMware' in out or 'Hyper-V' in out or 'VirtualBox' in out:
                indicators.append('systeminfo virtual indicator')
        except:
            pass
        if winreg:
            try:
                reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Services")
                subkeys = [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
                if 'VBoxService' in subkeys:
                    indicators.append('VirtualBox service')
                if 'vmware' in subkeys:
                    indicators.append('VMware service')
            except:
                pass
    elif OS_TYPE == 'Darwin':
        try:
            result = run_command(['system_profiler', 'SPHardwareDataType'])
            out = result.stdout
            if 'VMware' in out or 'Parallels' in out or 'VirtualBox' in out:
                indicators.append('virtual machine indicator')
        except:
            pass
    log("virtualization", "indicators", indicators)

def enum_permissions():
    perms = {}
    for p in ["/tmp", os.path.expanduser("~"), os.getcwd(), "/", "/etc"]:
        perms[p] = {
            "readable": os.access(p, os.R_OK),
            "writable": os.access(p, os.W_OK),
            "executable": os.access(p, os.X_OK)
        }
    RESULTS["permissions"] = perms

def enum_memory():
    if psutil:
        mem = psutil.virtual_memory()
        log("memory", "total_bytes", mem.total)
        log("memory", "available_bytes", mem.available)
        log("memory", "used_bytes", mem.used)
        log("memory", "free_bytes", mem.free)
        log("memory", "percent_used", mem.percent)
        log("memory", "buffers_bytes", mem.buffers if hasattr(mem, 'buffers') else None)
        log("memory", "cached_bytes", mem.cached if hasattr(mem, 'cached') else None)
    else:
        log("memory", "error", "psutil not installed")

def enum_swap():
    if psutil:
        swap = psutil.swap_memory()
        log("swap", "total_bytes", swap.total)
        log("swap", "used_bytes", swap.used)
        log("swap", "free_bytes", swap.free)
        log("swap", "percent_used", swap.percent)
    else:
        log("swap", "error", "psutil not installed")

def enum_uptime():
    if psutil:
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        log("system", "boot_time", datetime.fromtimestamp(boot_time).isoformat())
        log("system", "uptime_seconds", uptime)
    else:
        log("system", "uptime_error", "psutil not installed")

def enum_disk_partitions():
    if psutil:
        parts = psutil.disk_partitions()
        log("disk", "partitions", [p._asdict() for p in parts])
        for part in parts:
            try:
                usage = psutil.disk_usage(part.mountpoint)
                log("disk", f"usage_{part.mountpoint.replace('/', '_')}", {
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": usage.percent
                })
            except:
                pass
    else:
        log("disk", "error", "psutil not installed")

def enum_processes():
    if psutil:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                info['create_time'] = datetime.fromtimestamp(p.create_time()).isoformat()
                procs.append(info)
            except:
                pass
        log("processes", "list", procs)
    else:
        log("processes", "error", "psutil not installed")

def enum_logged_users():
    if psutil:
        users = psutil.users()
        log("users", "logged_in", [u._asdict() for u in users])
    else:
        log("users", "error", "psutil not installed")

def enum_services():
    services = {}
    if OS_TYPE == 'Windows':
        try:
            result = run_command(['sc', 'query', 'type=', 'service', 'state=', 'all'])
            lines = result.stdout.splitlines()
            current = None
            for line in lines:
                if line.startswith('SERVICE_NAME:'):
                    current = line.split(':', 1)[1].strip()
                    services[current] = {}
                elif current and ':' in line:
                    k, v = line.split(':', 1)
                    services[current][k.strip()] = v.strip()
        except Exception as e:
            services['error'] = str(e)
    elif OS_TYPE == 'Linux':
        try:
            result = run_command(['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--plain'])
            lines = result.stdout.splitlines()
            header_skipped = False
            for line in lines:
                if not header_skipped:
                    if line.startswith('UNIT'):
                        header_skipped = True
                    continue
                if line.strip():
                    parts = line.split(maxsplit=4)
                    if len(parts) >= 5:
                        name = parts[0]
                        load = parts[1]
                        active = parts[2]
                        sub = parts[3]
                        desc = parts[4]
                        services[name] = {'load': load, 'active': active, 'sub': sub, 'description': desc}
        except:
            try:
                result = run_command(['service', '--status-all'])
                services['raw_output'] = result.stdout.splitlines()
            except:
                services['error'] = 'No systemctl or service command found'
    elif OS_TYPE == 'Darwin':
        try:
            result = run_command(['launchctl', 'list'])
            lines = result.stdout.splitlines()
            for line in lines[1:]:  # skip header
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    pid = parts[0]
                    status = parts[1]
                    label = parts[2]
                    services[label] = {'pid': pid, 'status': status}
        except Exception as e:
            services['error'] = str(e)
    log("services", "list", services)

def enum_installed_apps():
    apps = []
    if OS_TYPE == 'Windows':
        try:
            result = run_command(['wmic', 'product', 'get', 'Name,Version', '/format:list'])
            lines = result.stdout.splitlines()
            current_name = None
            current_version = None
            for line in lines:
                if line.startswith('Name='):
                    if current_name and current_version:
                        apps.append({'name': current_name, 'version': current_version})
                    current_name = line[5:].strip()
                    current_version = None
                elif line.startswith('Version='):
                    current_version = line[8:].strip()
            if current_name and current_version:
                apps.append({'name': current_name, 'version': current_version})
        except:
            apps = [{'error': 'wmic failed'}]
    elif OS_TYPE == 'Linux':
        distro_id = ''
        distro_like = ''
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('ID='):
                        distro_id = line[3:].strip('"').lower()
                    elif line.startswith('ID_LIKE='):
                        distro_like = line[8:].strip('"').lower()
        distro = distro_id or distro_like

        if shutil.which('pacman'):
            try:
                result = run_command(['pacman', '-Q'])
                for line in result.stdout.splitlines():
                    if line.strip():
                        parts = line.split()
                        name = parts[0]
                        version = parts[1] if len(parts) > 1 else ''
                        apps.append({'package': name, 'version': version, 'arch': 'unknown'})
            except:
                pass

        if 'debian' in distro or 'ubuntu' in distro:
            try:
                result = run_command(['dpkg', '-l'])
                lines = result.stdout.splitlines()[5:]  # skip headers
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        apps.append({'package': parts[1], 'version': parts[2], 'arch': parts[3] if len(parts) > 3 else ''})
            except:
                apps.append({'error': 'dpkg failed'})
        elif 'fedora' in distro or 'rhel' in distro or 'centos' in distro or 'suse' in distro or 'redhat' in distro:
            try:
                result = run_command(['rpm', '-qa', '--qf', '%{NAME}|%{VERSION}|%{ARCH}\n'])
                for line in result.stdout.splitlines():
                    parts = line.split('|')
                    if len(parts) >= 2:
                        apps.append({'package': parts[0], 'version': parts[1], 'arch': parts[2] if len(parts) > 2 else ''})
            except:
                apps.append({'error': 'rpm failed'})
        else:
            if not shutil.which('pacman'):
                apps.append({'error': 'Unknown or unsupported distro'})
    elif OS_TYPE == 'Darwin':
        try:
            apps_dir = '/Applications'
            for item in os.listdir(apps_dir):
                if item.endswith('.app'):
                    apps.append({'name': item[:-4]})
        except:
            apps = [{'error': 'Failed to list /Applications'}]
    log("installed_apps", "list", apps)

def enum_browsers():
    browsers = []
    if OS_TYPE == 'Windows':
        common_paths = [
            r'C:\Program Files\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
            r'C:\Program Files\Mozilla Firefox\firefox.exe',
            r'C:\Program Files (x86)\Mozilla Firefox\firefox.exe',
            r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            r'C:\Program Files\Opera\opera.exe',
        ]
        for path in common_paths:
            if os.path.exists(path):
                browsers.append(os.path.basename(path)[:-4])
    elif OS_TYPE == 'Linux':
        common_cmds = ['google-chrome', 'google-chrome-stable', 'firefox', 'chromium', 'chromium-browser', 'opera']
        for cmd in common_cmds:
            if shutil.which(cmd):
                browsers.append(cmd)
    elif OS_TYPE == 'Darwin':
        common_apps = ['Google Chrome.app', 'Firefox.app', 'Safari.app', 'Opera.app', 'Microsoft Edge.app']
        for app in common_apps:
            if os.path.exists(os.path.join('/Applications', app)):
                browsers.append(app[:-4])
    log("browsers", "installed", browsers)

def enum_av():
    av = []
    if OS_TYPE == 'Windows':
        try:
            result = run_command([r'wmic', '/namespace:\\root\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName,productState', '/format:list'])
            lines = result.stdout.splitlines()
            for line in lines:
                if line.startswith('displayName='):
                    name = line[12:].strip()
                    if name:
                        av.append(name)
        except:
            av = ['error: wmic failed']
    elif OS_TYPE == 'Linux':
        common_av_cmds = ['clamd', 'freshclam', 'eset_nod32', 'mcafee', 'avast', 'avgd', 'bitdefender']
        for cmd in common_av_cmds:
            if shutil.which(cmd):
                av.append(cmd)
        try:
            result = run_command(['ls', '/lib/systemd/system'])
            av.extend([line.strip() for line in result.stdout.splitlines() if 'antivirus' in line.lower()])
        except:
            pass
    elif OS_TYPE == 'Darwin':
        av = ['XProtect (built-in)', 'Gatekeeper (built-in)']
        try:
            result = run_command(['mdfind', "kMDItemDisplayName == '*Antivirus*'"])
            av.extend([line.strip() for line in result.stdout.splitlines() if line.strip()])
        except:
            pass
    log("antivirus", "detected", list(set(av)))

def enum_security_features():
    sec = {}
    if OS_TYPE == 'Linux':
        try:
            result = run_command('getenforce')
            out = result.stdout.strip()
            sec['selinux'] = out or 'Not installed'
        except:
            sec['selinux'] = 'Not installed'
        try:
            result = run_command(['aa-status', '--enabled'])
            sec['apparmor'] = 'enabled' if result.returncode == 0 else 'disabled'
        except:
            sec['apparmor'] = 'Not installed'
        try:
            result = run_command(['ufw', 'status'])
            sec['ufw_firewall'] = result.stdout.strip()
        except:
            try:
                result = run_command(['iptables', '-L', '-n'])
                sec['iptables'] = 'Configured' if result.stdout.strip() else 'Not configured'
            except:
                sec['firewall'] = 'Unknown'
    elif OS_TYPE == 'Windows':
        if winreg:
            try:
                reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                key = winreg.OpenKey(reg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
                value = winreg.QueryValueEx(key, "EnableLUA")[0]
                sec['uac'] = 'Enabled' if value == 1 else 'Disabled'
            except:
                sec['uac'] = 'Unknown'
        try:
            result = run_command(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'])
            sec['firewall'] = result.stdout
        except:
            sec['firewall'] = 'Unknown'
    elif OS_TYPE == 'Darwin':
        try:
            result = run_command(['spctl', '--status'])
            sec['gatekeeper'] = result.stdout.strip()
        except:
            sec['gatekeeper'] = 'Unknown'
        try:
            result = run_command(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])
            sec['firewall'] = result.stdout.strip()
        except:
            sec['firewall'] = 'Unknown'
    log("security", "features", sec)

def enum_cloud_provider():
    provider = 'None detected'
    metadata = {}
    if OS_TYPE == 'Linux':
        dmi_path = '/sys/class/dmi/id/'
        if os.path.exists(dmi_path):
            try:
                with open(os.path.join(dmi_path, 'product_name')) as f:
                    name = f.read().strip()
                    metadata['product_name'] = name
                with open(os.path.join(dmi_path, 'bios_vendor')) as f:
                    vendor = f.read().strip()
                    metadata['bios_vendor'] = vendor
                if 'Amazon' in name or 'EC2' in name:
                    provider = 'AWS'
                elif 'Google' in name or 'Google' in vendor:
                    provider = 'GCP'
                elif 'Microsoft' in name or 'Azure' in name:
                    provider = 'Azure'
                elif 'Oracle' in name:
                    provider = 'Oracle Cloud'
            except:
                pass
    elif OS_TYPE == 'Windows':
        try:
            result = run_command('systeminfo')
            out = result.stdout
            if 'Microsoft Corporation' in out and 'Virtual Machine' in out:
                provider = 'Azure'
            elif 'Amazon' in out:
                provider = 'AWS'
        except:
            pass
    elif OS_TYPE == 'Darwin':
        try:
            result = run_command(['system_profiler', 'SPHardwareDataType'])
            out = result.stdout
            if 'AWS' in out or 'EC2' in out:
                provider = 'AWS'
        except:
            pass
    log("cloud", "provider", provider)
    log("cloud", "metadata", metadata)

def enum_kernel_modules():
    if OS_TYPE == 'Linux':
        try:
            result = run_command('lsmod')
            modules = []
            for line in result.stdout.splitlines()[1:]:
                if line.strip():
                    parts = line.split()
                    modules.append({'name': parts[0], 'size': parts[1], 'used': parts[2]})
            log("kernel", "modules", modules)
        except:
            log("kernel", "modules_error", "lsmod failed")
    else:
        log("kernel", "modules", "Not applicable on this OS")

def enum_scheduled_tasks():
    tasks = []
    if OS_TYPE in ['Linux', 'Darwin']:
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.hourly/',
            '/etc/cron.daily/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/',
            '/etc/cron.d/',
            '/var/spool/cron/',
            '/var/spool/cron/crontabs/'
        ]
        for path in cron_paths:
            if os.path.exists(path):
                if os.path.isdir(path):
                    for filename in os.listdir(path):
                        full_path = os.path.join(path, filename)
                        try:
                            with open(full_path, 'r') as f:
                                content = f.read()
                            tasks.append({'path': full_path, 'content': content})
                        except:
                            pass
                else:
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                        tasks.append({'path': path, 'content': content})
                    except:
                        pass
    elif OS_TYPE == 'Windows':
        try:
            result = run_command(['schtasks', '/query', '/fo', 'LIST', '/v'])
            current_task = {}
            for line in result.stdout.splitlines():
                if ':' in line:
                    k, v = line.split(':', 1)
                    k = k.strip()
                    v = v.strip()
                    if k == 'TaskName':
                        if current_task:
                            tasks.append(current_task)
                        current_task = {'TaskName': v}
                    else:
                        current_task[k] = v
            if current_task:
                tasks.append(current_task)
        except:
            tasks = [{'error': 'schtasks failed'}]
    log("scheduled", "tasks", tasks)

# ==============================
# ENUM DISPATCHER
# ==============================

def run_selected(args):
    if args.quick:
        enum_system()
        enum_user()

    if args.deep:
        enum_system()
        enum_network()
        enum_user()
        enum_resources()
        enum_env()
        enum_virtualization()
        enum_permissions()

    if args.full or args.all:
        enum_system()
        enum_network()
        enum_user()
        enum_resources()
        enum_env()
        enum_virtualization()
        enum_permissions()
        enum_memory()
        enum_swap()
        enum_uptime()
        enum_disk_partitions()
        enum_processes()
        enum_logged_users()
        enum_services()
        enum_installed_apps()
        enum_browsers()
        enum_av()
        enum_security_features()
        enum_cloud_provider()
        enum_kernel_modules()
        enum_scheduled_tasks()

    if args.system:
        enum_system()
    if args.network:
        enum_network()
    if args.user:
        enum_user()
    if args.resources:
        enum_resources()
    if args.env:
        enum_env()
    if args.vm:
        enum_virtualization()
    if args.perm:
        enum_permissions()
    if args.memory:
        enum_memory()
    if args.swap:
        enum_swap()
    if args.uptime:
        enum_uptime()
    if args.disks:
        enum_disk_partitions()
    if args.processes:
        enum_processes()
    if args.logged_users:
        enum_logged_users()
    if args.services:
        enum_services()
    if args.installed_apps:
        enum_installed_apps()
    if args.browsers:
        enum_browsers()
    if args.av:
        enum_av()
    if args.security:
        enum_security_features()
    if args.cloud:
        enum_cloud_provider()
    if args.kernel_modules:
        enum_kernel_modules()
    if args.scheduled:
        enum_scheduled_tasks()

# ==============================
# OUTPUT
# ==============================

def output_results(args, output_widget=None):
    data = {
        "timestamp": now_ts() if args.timestamp else None,
        "results": RESULTS
    }

    content = json.dumps(data, indent=2, ensure_ascii=False)
    if output_widget:
        output_widget.insert(tk.END, content + "\n\n")
        output_widget.see(tk.END)
    else:
        if args.json:
            plain_print_json(content)
        else:
            color_print_json(content)

    if args.save_dir:
        ensure_dir(args.save_dir)
        path = os.path.join(args.save_dir, "recon.json")
        mode = "a" if args.append else "w"
        with open(path, mode, encoding="utf-8") as f:
            f.write(content + "\n")

# ==============================
# GUI - حرفه‌ای، کاملاً دو زبانه، تم تاریک، با اسکرول عمودی کامل
# ==============================
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading

translations = {
    'en': {
        'title': 'LocalRecon - Advanced Enumeration Tool',
        'run': 'Run Scan',
        'clear': 'Clear Output',
        'exit': 'Exit',
        'language': 'Language:',
        'quick': 'Quick Scan',
        'deep': 'Deep Scan',
        'full': 'Full Scan',
        'scan_modes': 'Scan Modes',
        'modules': 'Select Modules',
        'options': 'Output Options',
        'json': 'JSON Output',
        'timestamp': 'Include Timestamp',
        'append': 'Append to File',
        'save_dir': 'Save Directory:',
        'browse': 'Browse',
        'results': 'Results',
        'starting': 'Starting enumeration...\n',
        'completed': 'Enumeration completed successfully!\n',
        'no_selection': 'Please select at least one scan mode or module.',
        'psutil_warning': 'Warning: psutil is not installed. Many modules will be limited.\nInstall with: pip install psutil',
    },
    'fa': {
        'title': 'LocalRecon - ابزار پیشرفته جمع‌آوری اطلاعات سیستم',
        'run': 'اجرای اسکن',
        'clear': 'پاک کردن خروجی',
        'exit': 'خروج',
        'language': 'زبان:',
        'quick': 'اسکن سریع',
        'deep': 'اسکن عمیق',
        'full': 'اسکن کامل',
        'scan_modes': 'حالت‌های اسکن',
        'modules': 'انتخاب ماژول‌ها',
        'options': 'گزینه‌های خروجی',
        'json': 'خروجی JSON',
        'timestamp': 'شامل زمان اجرا',
        'append': 'اضافه کردن به فایل',
        'save_dir': 'مسیر ذخیره:',
        'browse': 'انتخاب پوشه',
        'results': 'نتایج',
        'starting': 'در حال شروع جمع‌آوری اطلاعات...\n',
        'completed': 'جمع‌آوری اطلاعات با موفقیت به پایان رسید!\n',
        'no_selection': 'لطفاً حداقل یک حالت اسکن یا ماژول انتخاب کنید.',
        'psutil_warning': 'هشدار: psutil نصب نیست. بسیاری از ماژول‌ها محدود خواهند بود.\nنصب با: pip install psutil',
    }
}

module_names_fa = {
    'system': 'سیستم', 'network': 'شبکه', 'user': 'کاربر', 'resources': 'منابع',
    'env': 'محیط', 'vm': 'مجازی‌سازی', 'perm': 'مجوزها', 'memory': 'حافظه',
    'swap': 'سواپ', 'uptime': 'زمان اجرا', 'disks': 'دیسک‌ها', 'processes': 'پروسس‌ها',
    'logged_users': 'کاربران لاگین‌شده', 'services': 'سرویس‌ها', 'installed_apps': 'برنامه‌های نصب‌شده',
    'browsers': 'مرورگرها', 'av': 'آنتی‌ویروس', 'security': 'ویژگی‌های امنیتی',
    'cloud': 'ابر', 'kernel_modules': 'ماژول‌های کرنل', 'scheduled': 'وظایف زمان‌بندی‌شده'
}

module_names_en = {
    'system': 'System', 'network': 'Network', 'user': 'User', 'resources': 'Resources',
    'env': 'Environment', 'vm': 'Virtualization', 'perm': 'Permissions', 'memory': 'Memory',
    'swap': 'Swap', 'uptime': 'Uptime', 'disks': 'Disks', 'processes': 'Processes',
    'logged_users': 'Logged Users', 'services': 'Services', 'installed_apps': 'Installed Apps',
    'browsers': 'Browsers', 'av': 'Antivirus', 'security': 'Security Features',
    'cloud': 'Cloud Provider', 'kernel_modules': 'Kernel Modules', 'scheduled': 'Scheduled Tasks'
}

class Args:
    def __init__(self):
        self.quick = self.deep = self.full = self.all = False
        self.json = self.timestamp = self.append = False
        self.save_dir = None
        self.system = self.network = self.user = self.resources = False
        self.env = self.vm = self.perm = self.memory = self.swap = False
        self.uptime = self.disks = self.processes = self.logged_users = False
        self.services = self.installed_apps = self.browsers = self.av = False
        self.security = self.cloud = self.kernel_modules = self.scheduled = False

class LocalReconGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("LocalRecon")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0d1117")

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#0d1117')
        style.configure('TLabel', background='#0d1117', foreground='#c9d1d9', font=('Segoe UI', 10))
        style.configure('TLabelframe', background='#0d1117', foreground='#58a6ff')
        style.configure('TLabelframe.Label', background='#0d1117', foreground='#58a6ff', font=('Segoe UI', 12, 'bold'))
        style.configure('TButton', font=('Segoe UI', 11, 'bold'), padding=12)
        style.map('TButton', background=[('active', '#21262d')])
        style.configure('TCheckbutton', background='#0d1117', foreground='#c9d1d9', font=('Segoe UI', 10))
        style.configure('Horizontal.TProgressbar', background='#58a6ff', troughcolor='#21262d')

        self.current_lang = 'fa'
        self.module_vars = {}
        self.module_checks = {}

        # ایجاد اسکرول عمودی برای کل محتوا
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_container, bg="#0d1117", highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # پشتیبانی از اسکرول با چرخ موس
        def _on_mousewheel(event):
            canvas.yview_scroll(-1*(event.delta or event.num), "units" if hasattr(event, 'delta') else "pages")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)  # ویندوز و مک
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))  # لینوکس بالا
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))   # لینوکس پایین

        self.create_widgets()

        if not psutil:
            messagebox.showwarning("Warning", translations[self.current_lang]['psutil_warning'])

        self.update_language()

    def create_widgets(self):
        # تمام ویجت‌ها حالا داخل self.scrollable_frame ساخته می‌شن
        header = ttk.Frame(self.scrollable_frame)
        header.pack(fill=tk.X, pady=15, padx=25)

        title_frame = ttk.Frame(header)
        title_frame.pack(side=tk.LEFT)

        ttk.Label(title_frame, text="LocalRecon", font=("Segoe UI", 26, "bold"), foreground="#58a6ff").pack(anchor=tk.W)
        ttk.Label(title_frame, text="Powered by | Engineer Mahdi Zebardast Barzin", font=("Segoe UI", 10), foreground="#8b949e").pack(anchor=tk.W)

        lang_frame = ttk.Frame(header)
        lang_frame.pack(side=tk.RIGHT)
        self.lang_label = ttk.Label(lang_frame, text=translations['fa']['language'])
        self.lang_label.pack(side=tk.LEFT)
        self.lang_combo = ttk.Combobox(lang_frame, values=["English", "فارسی"], state="readonly", width=12)
        self.lang_combo.set("فارسی")
        self.lang_combo.pack(side=tk.LEFT, padx=10)
        self.lang_combo.bind("<<ComboboxSelected>>", self.change_language)

        # Scan Modes
        self.modes_frame = ttk.LabelFrame(self.scrollable_frame, text=translations['fa']['scan_modes'])
        self.modes_frame.pack(fill=tk.X, padx=25, pady=10)

        self.quick_var = tk.BooleanVar()
        self.quick_check = ttk.Checkbutton(self.modes_frame, text=translations['fa']['quick'], variable=self.quick_var)
        self.quick_check.grid(row=0, column=0, padx=60, pady=12)
        self.deep_var = tk.BooleanVar()
        self.deep_check = ttk.Checkbutton(self.modes_frame, text=translations['fa']['deep'], variable=self.deep_var)
        self.deep_check.grid(row=0, column=1, padx=60, pady=12)
        self.full_var = tk.BooleanVar()
        self.full_check = ttk.Checkbutton(self.modes_frame, text=translations['fa']['full'], variable=self.full_var)
        self.full_check.grid(row=0, column=2, padx=60, pady=12)

        # Modules
        self.modules_frame = ttk.LabelFrame(self.scrollable_frame, text=translations['fa']['modules'])
        self.modules_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=10)

        modules = list(module_names_fa.keys())
        for i, mod in enumerate(modules):
            var = tk.BooleanVar()
            self.module_vars[mod] = var
            check = ttk.Checkbutton(self.modules_frame, text=module_names_fa[mod], variable=var)
            check.grid(row=i // 5, column=i % 5, sticky=tk.W, padx=20, pady=6)
            self.module_checks[mod] = check

        # Output Options
        self.options_frame = ttk.LabelFrame(self.scrollable_frame, text=translations['fa']['options'])
        self.options_frame.pack(fill=tk.X, padx=25, pady=10)

        self.json_var = tk.BooleanVar()
        self.json_check = ttk.Checkbutton(self.options_frame, text=translations['fa']['json'], variable=self.json_var)
        self.json_check.grid(row=0, column=0, padx=40, pady=12, sticky=tk.W)
        self.timestamp_var = tk.BooleanVar()
        self.timestamp_check = ttk.Checkbutton(self.options_frame, text=translations['fa']['timestamp'], variable=self.timestamp_var)
        self.timestamp_check.grid(row=0, column=1, padx=40, pady=12, sticky=tk.W)
        self.append_var = tk.BooleanVar()
        self.append_check = ttk.Checkbutton(self.options_frame, text=translations['fa']['append'], variable=self.append_var)
        self.append_check.grid(row=0, column=2, padx=40, pady=12, sticky=tk.W)

        self.save_label = ttk.Label(self.options_frame, text=translations['fa']['save_dir'])
        self.save_label.grid(row=1, column=0, sticky=tk.E, padx=20)
        self.save_entry = ttk.Entry(self.options_frame, width=85)
        self.save_entry.grid(row=1, column=1, columnspan=2, padx=20, pady=12, sticky=tk.W+tk.E)
        self.browse_button = ttk.Button(self.options_frame, text=translations['fa']['browse'], command=self.browse_dir)
        self.browse_button.grid(row=1, column=3, padx=20)

        # Results
        self.results_frame = ttk.LabelFrame(self.scrollable_frame, text=translations['fa']['results'])
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=10)

        self.output_text = scrolledtext.ScrolledText(self.results_frame, bg="#161b22", fg="#c9d1d9", font=("Consolas", 11), insertbackground="white")
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Buttons
        buttons_frame = ttk.Frame(self.scrollable_frame)
        buttons_frame.pack(fill=tk.X, pady=25, padx=25)

        self.run_button = ttk.Button(buttons_frame, text=translations['fa']['run'], command=self.start_scan)
        self.run_button.pack(side=tk.LEFT, padx=30)

        self.clear_button = ttk.Button(buttons_frame, text=translations['fa']['clear'], command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=15)
        self.exit_button = ttk.Button(buttons_frame, text=translations['fa']['exit'], command=self.root.quit)
        self.exit_button.pack(side=tk.RIGHT, padx=30)

        self.progress = ttk.Progressbar(buttons_frame, orient="horizontal", mode="indeterminate")
        self.progress.pack(side=tk.RIGHT, padx=60, fill=tk.X, expand=True)

        # Footer - github link
        footer = ttk.Frame(self.scrollable_frame)
        footer.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(footer, text="github | https://github.com/mahdizebardastbarzin", font=("Segoe UI", 10), foreground="#8b949e").pack()

    def browse_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.save_entry.delete(0, tk.END)
            self.save_entry.insert(0, directory)

    def change_language(self, event=None):
        selected = self.lang_combo.get()
        self.current_lang = 'en' if selected == "English" else 'fa'
        self.update_language()

    def update_language(self):
        t = translations[self.current_lang]
        module_names = module_names_en if self.current_lang == 'en' else module_names_fa

        self.root.title(t['title'])
        self.lang_label.configure(text=t['language'])
        self.modes_frame.configure(text=t['scan_modes'])
        self.modules_frame.configure(text=t['modules'])
        self.options_frame.configure(text=t['options'])
        self.results_frame.configure(text=t['results'])
        self.run_button.configure(text=t['run'])
        self.clear_button.configure(text=t['clear'])
        self.exit_button.configure(text=t['exit'])
        self.browse_button.configure(text=t['browse'])
        self.save_label.configure(text=t['save_dir'])
        self.json_check.configure(text=t['json'])
        self.timestamp_check.configure(text=t['timestamp'])
        self.append_check.configure(text=t['append'])
        self.quick_check.configure(text=t['quick'])
        self.deep_check.configure(text=t['deep'])
        self.full_check.configure(text=t['full'])

        for mod, check in self.module_checks.items():
            check.configure(text=module_names[mod])

    def start_scan(self):
        selected = (self.quick_var.get() or self.deep_var.get() or self.full_var.get() or
                    any(v.get() for v in self.module_vars.values()))
        if not selected:
            messagebox.showwarning("Warning", translations[self.current_lang]['no_selection'])
            return

        self.progress.start()
        self.run_button.config(state="disabled")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, translations[self.current_lang]['starting'])

        args = Args()
        args.quick = self.quick_var.get()
        args.deep = self.deep_var.get()
        args.full = self.full_var.get()
        args.all = self.full_var.get()
        args.json = self.json_var.get()
        args.timestamp = self.timestamp_var.get()
        args.append = self.append_var.get()
        args.save_dir = self.save_entry.get() or None

        for mod, var in self.module_vars.items():
            setattr(args, mod, var.get())

        threading.Thread(target=self.execute_scan, args=(args,), daemon=True).start()

    def execute_scan(self, args):
        global RESULTS
        RESULTS = {}
        run_selected(args)
        self.root.after(0, lambda: self.finish_scan(args))

    def finish_scan(self, args):
        output_results(args, self.output_text)
        self.output_text.insert(tk.END, translations[self.current_lang]['completed'])
        self.progress.stop()
        self.run_button.config(state="normal")

    def clear_output(self):
        self.output_text.delete(1.0, tk.END)

# ==============================
# MAIN
# ==============================

def main():
    parser = argparse.ArgumentParser(description="LocalRecon - Modular System Enumeration Tool")

    parser.add_argument("--gui", action="store_true", help="Run in GUI mode")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timestamp", action="store_true")
    parser.add_argument("--system", action="store_true")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--user", action="store_true")
    parser.add_argument("--resources", action="store_true")
    parser.add_argument("--env", action="store_true")
    parser.add_argument("--vm", action="store_true")
    parser.add_argument("--perm", action="store_true")
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--swap", action="store_true")
    parser.add_argument("--uptime", action="store_true")
    parser.add_argument("--disks", action="store_true")
    parser.add_argument("--processes", action="store_true")
    parser.add_argument("--logged_users", action="store_true")
    parser.add_argument("--services", action="store_true")
    parser.add_argument("--installed_apps", action="store_true")
    parser.add_argument("--browsers", action="store_true")
    parser.add_argument("--av", action="store_true")
    parser.add_argument("--security", action="store_true")
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--kernel_modules", action="store_true")
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--save-dir", metavar="DIR")
    parser.add_argument("--append", action="store_true")

    args = parser.parse_args()

    if args.gui or len(sys.argv) == 1:
        LocalReconGUI().root.mainloop()
    else:
        if not psutil:
            print(f"{C.YELLOW}[!] WARNING: psutil is not installed. Many important modules will not work properly.{C.RESET}")
            print("    Please install it with: pip install psutil\n")

        banner()
        run_selected(args)

        if not RESULTS:
            print("[!] No enumeration selected")
            parser.print_help()
            sys.exit(0)

        output_results(args)

if __name__ == "__main__":
    main()