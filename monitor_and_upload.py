import os
import time
from dotenv import load_dotenv
import paramiko
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
from logging.handlers import TimedRotatingFileHandler
from azure.storage.blob import BlobServiceClient
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from threading import Thread
import json

# ======== โหลด ENV =========
'''load_dotenv(dotenv_path="config.env")
SFTP_HOST = os.getenv("SFTP_HOST")
SFTP_PORT = int(os.getenv("SFTP_PORT", 22))
SFTP_USER = os.getenv("SFTP_USER")
SFTP_PASS = os.getenv("SFTP_PASS")'''
#REMOTE_DIR = "./COOP"
WATCH_FOLDER = "C:/Users/Boat_/Downloads/watch_folder"
'''AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME")
assert AZURE_CONNECTION_STRING is not None, "❌ Missing AZURE_CONNECTION_STRING"
assert AZURE_CONTAINER_NAME is not None, "❌ Missing AZURE_CONTAINER_NAME"'''

# ======== Logger =========
def setup_logger(log_dir="logs"):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, "upload.log")
    logger = logging.getLogger("UploadLogger")
    logger.setLevel(logging.DEBUG)
    handler = TimedRotatingFileHandler(
        log_file, when="midnight", interval=1, backupCount=7, encoding='utf-8'
    )
    handler.suffix = "%Y-%m-%d"
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

logger = setup_logger()

# ======== Key management =========
def generate_key(save_to="secret.key"):
    key = Fernet.generate_key()
    with open(save_to, "wb") as f:
        f.write(key)

def load_key(key_path="secret.key"):
    if not os.path.exists(key_path):
        generate_key(key_path)
    return open(key_path, "rb").read()

# ======== Encrypt file =========
def encrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    encrypted_path = filepath + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)
    logger.info(f"🔐 เข้ารหัสไฟล์: {os.path.basename(filepath)} → {os.path.basename(encrypted_path)}")
    return encrypted_path

# ======== ตรวจว่าไฟล์พร้อม =========
def wait_for_file_ready(filepath, timeout=15):
    prev_size = -1
    stable_count = 0
    start = time.time()
    while time.time() - start < timeout:
        try:
            size = os.path.getsize(filepath)
            if size == prev_size:
                stable_count += 1
                if stable_count >= 4:
                    return True
            else:
                stable_count = 0
            prev_size = size
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False

# ======== Upload to Azure =========
def upload_to_blob(filepath):
    try:
        blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
        container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)
        try:
            container_client.create_container()
        except:
            pass
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as data:
            container_client.upload_blob(name=filename, data=data, overwrite=True)
        logger.info(f"✅ [Azure] อัปโหลดสำเร็จ: {filename}")
    except Exception as e:
        logger.error(f"❌ [Azure] อัปโหลดล้มเหลว: {filepath} | {e}")

# ======== รวม log และ upload =========
def log_upload(filepath):
    try:
        size_kb = os.path.getsize(filepath) / 1024
        logger.info(f"🟢 เริ่มอัปโหลด: {filepath} ({size_kb:.2f} KB)")
        upload_to_blob(filepath)
        logger.info(f"✅ อัปโหลดเสร็จ: {filepath}")
    except Exception as e:
        logger.error(f"❌ log_upload ล้มเหลว: {e}")

# ======== Watchdog Handler =========
class UploadHandler(FileSystemEventHandler):
    def __init__(self, host, port, username, password, remote_dir):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.remote_dir = remote_dir
        
    def on_created(self, event):
        if not event.is_directory:
            filepath = os.path.abspath(event.src_path)
            filename = os.path.basename(filepath)
            logger.info(f"[EVENT] พบไฟล์ใหม่: {filename}")

            if filename.endswith(".enc"):
                logger.info(f"[SKIP] ข้ามไฟล์ .enc: {filename}")
                return

            if not wait_for_file_ready(filepath):
                logger.warning(f"[SKIP] ไฟล์ {filename} ยังไม่พร้อมใช้งาน")
                return

            # 🔐 เข้ารหัสก่อนอัปโหลด
            key = load_key()
            encrypted_path = encrypt_file(filepath, key)
            encrypted_filename = os.path.basename(encrypted_path)

            try:
                transport = paramiko.Transport((self.host, self.port))
                transport.connect(username=self.username, password=self.password)
                sftp = paramiko.SFTPClient.from_transport(transport)

                remote_path = os.path.join(self.remote_dir, encrypted_filename).replace("\\", "/")

                if not os.path.exists(encrypted_path):
                    logger.error(f"[ERROR] ไฟล์เข้ารหัสหายไป: {encrypted_path}")
                    return

                remote_path = os.path.join(self.remote_dir, encrypted_filename).replace("\\", "/")
                # ==================== Create path if not===================
                try:
                    sftp.mkdir(self.remote_dir)
                except IOError:
                    pass

                sftp.put(encrypted_path, remote_path)
                logger.info(f"✅ [SFTP] อัปโหลดสำเร็จ: {encrypted_filename}")

                sftp.close()
                transport.close()

                # 📤 Upload to Azure + log
                log_upload(encrypted_path)

            except Exception as e:
                logger.error(f"[ERROR] อัปโหลดล้มเหลว: {encrypted_filename} | {e}")
                logger.debug(f"[DEBUG] path: {encrypted_path}")

# ======== Download files =========
def download_from_sftp(filename,remote_dir, host, port, username, password, save_to="downloads" ):
    try:
        if not os.path.exists(save_to):
            os.makedirs(save_to)

        transport = paramiko.Transport((host, port))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        remote_path = os.path.join(remote_dir, filename).replace("\\", "/")
        local_path = os.path.join(save_to, filename)

        sftp.get(remote_path, local_path)
        sftp.close()
        transport.close()

        logger.info(f"✅ ดาวน์โหลดไฟล์สำเร็จ: {filename}")
        return local_path

    except Exception as e:
        logger.error(f"❌ ดาวน์โหลดล้มเหลว: {filename} | {e}")
        return None
 
# ======== Decrypt files =========
def decrypt_file(filepath, key):
    try:
        fernet = Fernet(key)
        with open(filepath, "rb") as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)

        output_path = filepath[:-4] if filepath.endswith(".enc") else filepath + ".dec"
        with open(output_path, "wb") as dec_file:
            dec_file.write(decrypted)

        logger.info(f"✅ ถอดรหัสแล้ว: {os.path.basename(filepath)} → {os.path.basename(output_path)}")
        return output_path
    except Exception as e:
        logger.error(f"❌ ถอดรหัสล้มเหลว: {e}")
        return None

# ======== GUI Application =========
class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.sftp_profile_manager = SftpProfileManager()
        self.current_sftp_profile = None
        self.root.title("ระบบอัปโหลดและดาวน์โหลดไฟล์แบบปลอดภัย")
        self.root.geometry("1000x700")
        

        self.sftp_status_var = tk.StringVar()
        self.sftp_status_var.set("ยังไม่ได้เลือกเซิร์ฟเวอร์ SFTP")
        self.status_var = tk.StringVar()  # เพิ่มบรรทัดนี้ด้วย
        self.status_var.set("พร้อมเริ่มการตรวจสอบ")
        # สร้าง Tab ควบคุม
        self.tab_control = ttk.Notebook(root)
        
        # เพิ่มเมนูจัดการ SFTP
        self._setup_sftp_menu()

        # แท็บการตรวจสอบไฟล์
        self.tab_monitor = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_monitor, text='การตรวจสอบไฟล์')
        
        # แท็บดาวน์โหลดไฟล์
        self.tab_download = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_download, text='ดาวน์โหลดไฟล์')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # ส่วนแสดง Log
        self.log_frame = ttk.LabelFrame(root, text="บันทึกเหตุการณ์")
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_text.configure(state='disabled')
        
        # ส่วนควบคุมการทำงาน (แก้ไขส่วนนี้)
        self.create_control_buttons()
        
        # ปุ่มเริ่มตรวจสอบ (ประกาศเพียงครั้งเดียว)
        self.btn_start = ttk.Button(
            self.control_frame,
            text="เริ่มตรวจสอบ",
            command=self.start_monitoring,
            style='Start.TButton'
        )
        self.btn_start.pack(side="left", padx=5)

        # ปุ่มหยุดตรวจสอบ
        self.btn_stop = ttk.Button(
            self.control_frame, 
            text="หยุดตรวจสอบ", 
            command=self.stop_monitoring, 
            state='disabled',
            style='Stop.TButton'
        )
        self.btn_stop.pack(side="left", padx=5)

        # ปุ่มล้างบันทึก
        self.btn_clear_log = ttk.Button(
            self.control_frame, 
            text="ล้างบันทึก", 
            command=self.clear_log
        )
        self.btn_clear_log.pack(side="right", padx=5)
        
        # กำหนดสไตล์ปุ่ม
        self.setup_button_styles()

        # ตั้งค่าแท็บต่างๆ
        self.setup_monitor_tab()
        self.setup_download_tab()
        
        # ตัวแปรสำหรับการตรวจสอบไฟล์
        self.observer = None
        self.event_handler = None
        self.monitoring = False
        
        # Redirect logger to GUI
        self.setup_log_redirect()

    def _setup_sftp_menu(self):
        """เพิ่มเมนูจัดการ SFTP"""
        menubar = tk.Menu(self.root)
        
        # เมนู SFTP
        sftp_menu = tk.Menu(menubar, tearoff=0)
        sftp_menu.add_command(
            label="เลือกเซิร์ฟเวอร์ SFTP", 
            command=self._select_sftp_profile
        )
        sftp_menu.add_separator()
        sftp_menu.add_command(
            label="จัดการเซิร์ฟเวอร์ SFTP", 
            command=self._manage_sftp_profiles
        )
        
        menubar.add_cascade(label="SFTP", menu=sftp_menu)
        self.root.config(menu=menubar)
    
    def _select_sftp_profile(self):
        """เปิดหน้าต่างเลือกเซิร์ฟเวอร์ SFTP"""
        SftpProfileWindow(
            self.root,
            self.sftp_profile_manager,
            self._on_sftp_profile_selected
        )
    
    def _manage_sftp_profiles(self):
        """เปิดหน้าต่างจัดการเซิร์ฟเวอร์ SFTP"""
        SftpProfileWindow(self.root, self.sftp_profile_manager)
    
    def _on_sftp_profile_selected(self, profile):
        """เมื่อเลือกเซิร์ฟเวอร์ SFTP แล้ว"""
        self.current_sftp_profile = profile
        messagebox.showinfo(
            "เลือกเซิร์ฟเวอร์แล้ว",
            f"เลือกเซิร์ฟเวอร์: {profile['host']}\n"
            f"โฟลเดอร์ปลายทาง: {profile['remote_dir']}"
        )
        
        # อัปเดตสถานะใน GUI
        self._update_sftp_status()
    
    def _update_sftp_status(self):
        """อัปเดตสถานะเซิร์ฟเวอร์ SFTP ใน GUI"""
        if self.current_sftp_profile:
            status_text = (
                f"เซิร์ฟเวอร์: {self.current_sftp_profile['host']} | "
                f"ผู้ใช้: {self.current_sftp_profile['username']} | "
                f"โฟลเดอร์: {self.current_sftp_profile['remote_dir']}"
            )
            self.sftp_status_var.set(status_text)
        else:
            self.sftp_status_var.set("ยังไม่ได้เลือกเซิร์ฟเวอร์ SFTP")
    
    def start_monitoring(self):
        """เริ่มการตรวจสอบไฟล์ - ปรับปรุงให้ใช้ SFTP ที่เลือก"""
        if not self.current_sftp_profile:
            messagebox.showerror("ข้อผิดพลาด", "กรุณาเลือกเซิร์ฟเวอร์ SFTP ก่อน")
            return
        
        watch_folder = self.watch_folder_var.get()
        if not os.path.isdir(watch_folder):
            messagebox.showerror("ข้อผิดพลาด", "โฟลเดอร์ที่ระบุไม่มีอยู่!")
            return
            
        try:
            # ตรวจสอบว่า observer กำลังทำงานอยู่หรือไม่
            if hasattr(self, 'observer') and self.observer and self.observer.is_alive():
                messagebox.showwarning("คำเตือน", "ระบบกำลังตรวจสอบไฟล์อยู่แล้ว")
                return
                
            # สร้าง handler ด้วยโปรไฟล์ SFTP ที่เลือก
            self.event_handler = UploadHandler(
                self.current_sftp_profile['host'],
                int(self.current_sftp_profile['port']),
                self.current_sftp_profile['username'],
                self.current_sftp_profile['password'],
                self.current_sftp_profile['remote_dir']
            )
            
            self.observer = Observer()
            self.observer.schedule(self.event_handler, path=watch_folder, recursive=False)
            self.observer.start()
            
            self.monitoring = True
            self.status_var.set(f"กำลังตรวจสอบโฟลเดอร์: {watch_folder}")
            self.btn_start.config(state='disabled')
            self.btn_stop.config(state='normal')
            logger.info(f"🟢 เริ่มตรวจสอบโฟลเดอร์: {watch_folder}")
            messagebox.showinfo("สำเร็จ", "เริ่มการตรวจสอบไฟล์เรียบร้อยแล้ว")
        except Exception as e:
            logger.error(f"❌ เริ่มการตรวจสอบล้มเหลว: {e}")
            messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถเริ่มการตรวจสอบได้: {e}")
    
    def create_control_buttons(self):
        # เฟรมสำหรับปุ่มควบคุม
        self.control_frame = ttk.Frame(self.root)
        self.control_frame.pack(fill="x", padx=10, pady=5, before=self.log_frame)  # วางก่อนส่วนแสดง Log

    def setup_button_styles(self):
        style = ttk.Style()
        style.configure('Start.TButton', foreground='green', font=('Tahoma', 10, 'bold'))
        style.configure('Stop.TButton', foreground='red', font=('Tahoma', 10, 'bold'))
            
    def stop_monitoring(self):
        if hasattr(self, 'observer') and self.observer:
            try:
                if hasattr(self.observer, 'is_alive') and self.observer.is_alive():
                    self.observer.stop()
                    self.observer.join()
                    
                self.monitoring = False
                self.status_var.set("หยุดการตรวจสอบแล้ว")
                
                # ปรับสถานะปุ่ม
                self.btn_start.config(state='normal')
                self.btn_stop.config(state='disabled')
                
                logger.info("🛑 หยุดการตรวจสอบโฟลเดอร์")
                messagebox.showinfo("สำเร็จ", "หยุดการตรวจสอบไฟล์เรียบร้อยแล้ว")
                
            except Exception as e:
                logger.error(f"❌ หยุดการตรวจสอบล้มเหลว: {e}")
                messagebox.showerror("ข้อผิดพลาด", 
                                   f"ไม่สามารถหยุดการตรวจสอบได้:\n{str(e)}", 
                                   icon='error')
    
    def setup_monitor_tab(self):
        # กรอบตั้งค่าโฟลเดอร์
        frame = ttk.LabelFrame(self.tab_monitor, text="ตั้งค่าโฟลเดอร์ตรวจสอบ")
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="โฟลเดอร์ที่ตรวจสอบ:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        
        self.watch_folder_var = tk.StringVar(value=WATCH_FOLDER)
        self.entry_watch = ttk.Entry(frame, textvariable=self.watch_folder_var, width=50)
        self.entry_watch.grid(row=0, column=1, padx=5, pady=5)
        
        #============================== เพิ่มส่วนแสดงสถานะ SFTP ======================
        sftp_status_frame = ttk.LabelFrame(self.tab_monitor, text="สถานะเซิร์ฟเวอร์ SFTP")
        sftp_status_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(sftp_status_frame, textvariable=self.sftp_status_var).pack(padx=5, pady=5)

        self.btn_browse = ttk.Button(frame, text="เลือกโฟลเดอร์", command=self.browse_folder)
        self.btn_browse.grid(row=0, column=2, padx=5, pady=5)
        
        # กรอบสถานะ
        status_frame = ttk.LabelFrame(self.tab_monitor, text="สถานะการทำงาน")
        status_frame.pack(fill="x", padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="พร้อมเริ่มการตรวจสอบ")
        ttk.Label(status_frame, textvariable=self.status_var).pack(padx=5, pady=5)
        
        # ส่วนแสดงไฟล์ท้องถิ่น
        local_frame = ttk.LabelFrame(self.tab_monitor, text="ไฟล์ในโฟลเดอร์ท้องถิ่น")
        local_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # สร้าง Treeview
        self.local_tree = ttk.Treeview(local_frame, columns=("name", "size", "modified"), show="headings")
        self.local_tree.heading("name", text="ชื่อไฟล์")
        self.local_tree.heading("size", text="ขนาด (KB)")
        self.local_tree.heading("modified", text="แก้ไขล่าสุด")
        self.local_tree.column("name", width=250)
        self.local_tree.column("size", width=100)
        self.local_tree.column("modified", width=150)
        
        # Scrollbar
        vsb = ttk.Scrollbar(local_frame, orient="vertical", command=self.local_tree.yview)
        hsb = ttk.Scrollbar(local_frame, orient="horizontal", command=self.local_tree.xview)
        self.local_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.local_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # ปุ่มรีเฟรช
        btn_refresh = ttk.Button(local_frame, text="รีเฟรช", command=self.refresh_local_files)
        btn_refresh.grid(row=2, column=0, pady=5)
        
    
    
    def setup_download_tab(self):
        # กรอบดาวน์โหลดไฟล์
        frame = ttk.LabelFrame(self.tab_download, text="ดาวน์โหลดไฟล์จากเซิร์ฟเวอร์")
        frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(frame, text="ชื่อไฟล์ที่ต้องการดาวน์โหลด:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        
        self.download_filename_var = tk.StringVar()
        self.entry_download = ttk.Entry(frame, textvariable=self.download_filename_var, width=40)
        self.entry_download.grid(row=0, column=1, padx=5, pady=5)
        
        self.btn_download = ttk.Button(frame, text="ดาวน์โหลด", command=self.handle_download)
        self.btn_download.grid(row=0, column=2, padx=5, pady=5)
        
        # กรอบถอดรหัสไฟล์
        decrypt_frame = ttk.LabelFrame(self.tab_download, text="ถอดรหัสไฟล์")
        decrypt_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(decrypt_frame, text="ไฟล์ที่เข้ารหัส:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        
        self.encrypted_file_var = tk.StringVar()
        self.entry_encrypted = ttk.Entry(decrypt_frame, textvariable=self.encrypted_file_var, width=40)
        self.entry_encrypted.grid(row=0, column=1, padx=5, pady=5)
        
        self.btn_browse_enc = ttk.Button(decrypt_frame, text="เลือกไฟล์", command=self.browse_encrypted_file)
        self.btn_browse_enc.grid(row=0, column=2, padx=5, pady=5)
        
        self.btn_decrypt = ttk.Button(decrypt_frame, text="ถอดรหัส", command=self.handle_decrypt)
        self.btn_decrypt.grid(row=1, column=1, pady=5)
        
        # ส่วนแสดงไฟล์บนเซิร์ฟเวอร์
        remote_frame = ttk.LabelFrame(self.tab_download, text="ไฟล์บนเซิร์ฟเวอร์ SFTP")
        remote_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # สร้าง Treeview
        self.remote_tree = ttk.Treeview(remote_frame, columns=("name", "size", "modified"), show="headings")
        self.remote_tree.heading("name", text="ชื่อไฟล์")
        self.remote_tree.heading("size", text="ขนาด (KB)")
        self.remote_tree.heading("modified", text="แก้ไขล่าสุด")
        self.remote_tree.column("name", width=250)
        self.remote_tree.column("size", width=100)
        self.remote_tree.column("modified", width=150)
        
        # Scrollbar
        vsb = ttk.Scrollbar(remote_frame, orient="vertical", command=self.remote_tree.yview)
        hsb = ttk.Scrollbar(remote_frame, orient="horizontal", command=self.remote_tree.xview)
        self.remote_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.remote_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # ปุ่มควบคุม
        btn_frame = ttk.Frame(remote_frame)
        btn_frame.grid(row=2, column=0, pady=5)
        
        btn_refresh = ttk.Button(btn_frame, text="รีเฟรช", command=self.refresh_remote_files)
        btn_refresh.pack(side="left", padx=5)
        
        btn_download = ttk.Button(btn_frame, text="ดาวน์โหลดที่เลือก", command=self.download_selected)
        btn_download.pack(side="left", padx=5)
        
        # โหลดไฟล์ครั้งแรก
        self.refresh_remote_files()
    
    def setup_log_redirect(self):
        class GuiLogHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
            
            def emit(self, record):
                msg = self.format(record)
                self.text_widget.configure(state='normal')
                self.text_widget.insert("end", msg + "\n")
                self.text_widget.configure(state='disabled')
                self.text_widget.see("end")
        
        gui_handler = GuiLogHandler(self.log_text)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(gui_handler)
    
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.watch_folder_var.set(folder)
            self.refresh_local_files()
    
    def browse_encrypted_file(self):
        file = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if file:
            self.encrypted_file_var.set(file)
    
    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            self.status_var.set("หยุดการตรวจสอบแล้ว")
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
            logger.info("🛑 หยุดการตรวจสอบโฟลเดอร์")
    
    def handle_download(self):
        fname = self.download_filename_var.get().strip()
        if not fname:
            messagebox.showwarning("คำเตือน", "โปรดใส่ชื่อไฟล์ที่ต้องการดาวน์โหลด")
            return
        
        Thread(target=self._download_and_decrypt, args=(fname,)).start()
    
    def _download_and_decrypt(self, fname):
        try:

            if not self.current_sftp_profile:
                messagebox.showerror("ข้อผิดพลาด", "กรุณาเลือกเซิร์ฟเวอร์ SFTP ก่อน")
                return None

            result = download_from_sftp(
                filename=fname,
                remote_dir=self.current_sftp_profile['remote_dir'],
                host=self.current_sftp_profile['host'],
                port=self.current_sftp_profile['port'],
                username=self.current_sftp_profile['username'],
                password=self.current_sftp_profile['password']
            )

            #result = download_from_sftp(fname, self.current_sftp_profile['remote_dir'])
            if result:

                key = load_key()
                decrypted = decrypt_file(result, key)
                if decrypted:
                    messagebox.showinfo("สำเร็จ", f"✅ ดาวน์โหลดและถอดรหัสแล้ว:\n{os.path.basename(decrypted)}")
                else:
                    messagebox.showerror("ล้มเหลว", f"❌ ถอดรหัสไฟล์ไม่สำเร็จ:\n{fname}")
            else:
                messagebox.showerror("ล้มเหลว", f"❌ ดาวน์โหลดไฟล์ไม่สำเร็จ: {fname}")
        except Exception as e:
            messagebox.showerror("ข้อผิดพลาด", f"เกิดข้อผิดพลาด: {e}")
    
    def handle_decrypt(self):
        filepath = self.encrypted_file_var.get()
        if not filepath:
            messagebox.showwarning("คำเตือน", "โปรดเลือกไฟล์ที่ต้องการถอดรหัส")
            return
        
        if not filepath.endswith('.enc'):
            messagebox.showwarning("คำเตือน", "ไฟล์ต้องมีนามสกุล .enc เท่านั้น")
            return
        
        Thread(target=self._decrypt_file, args=(filepath,)).start()
    
    def _decrypt_file(self, filepath):
        try:
            key = load_key()
            decrypted = decrypt_file(filepath, key)
            if decrypted:
                messagebox.showinfo("สำเร็จ", f"✅ ถอดรหัสไฟล์สำเร็จ:\n{os.path.basename(decrypted)}")
            else:
                messagebox.showerror("ล้มเหลว", "❌ ถอดรหัสไฟล์ไม่สำเร็จ")
        except Exception as e:
            messagebox.showerror("ข้อผิดพลาด", f"เกิดข้อผิดพลาด: {e}")
    
    def refresh_remote_files(self):
        """รีเฟรชรายการไฟล์บนเซิร์ฟเวอร์"""
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)

        try:
            host = self.current_sftp_profile['host']
            port = self.current_sftp_profile['port']
            username = self.current_sftp_profile['username']
            password = self.current_sftp_profile['password']
            remote_dir = self.current_sftp_profile['remote_dir']

            transport = paramiko.Transport((host, port))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            files = sftp.listdir_attr(remote_dir)
            for file_attr in files:
                if not file_attr.filename.startswith('.'):
                    size = file_attr.st_size / 1024
                    mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_attr.st_mtime))
                    self.remote_tree.insert("", "end", values=(file_attr.filename, f"{size:.2f}", mtime))
            
            sftp.close()
            transport.close()
        except Exception as e:
            logger.error(f"❌ ไม่สามารถดึงรายการไฟล์จากเซิร์ฟเวอร์: {e}")
            messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์: {e}")
    
    def download_selected(self):
        selected_item = self.remote_tree.selection()
        if not selected_item:
            messagebox.showwarning("คำเตือน", "โปรดเลือกไฟล์ที่ต้องการดาวน์โหลด")
            return
        
        filename = self.remote_tree.item(selected_item)['values'][0]
        self.download_filename_var.set(filename)
        self.handle_download()
    
    def clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, "end")
        self.log_text.configure(state='disabled')
    
    def on_closing(self):
        if self.monitoring:
            self.stop_monitoring()
        self.root.destroy()
# ในคลาส FileTransferApp ให้เพิ่มเมธอดเหล่านี้

    def refresh_local_files(self):
        """รีเฟรชรายการไฟล์ในโฟลเดอร์ท้องถิ่น"""
        watch_folder = self.watch_folder_var.get()
        if not os.path.isdir(watch_folder):
            return
        
        # ล้างข้อมูลเก่า
        for item in self.local_tree.get_children():
            self.local_tree.delete(item)
        
        # เพิ่มไฟล์ใหม่
        for filename in os.listdir(watch_folder):
            filepath = os.path.join(watch_folder, filename)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath) / 1024  # KB
                mtime = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(os.path.getmtime(filepath)))
                self.local_tree.insert("", "end", values=(filename, f"{size:.2f}", mtime))

    def refresh_remote_files(self):
        """รีเฟรชรายการไฟล์บนเซิร์ฟเวอร์ SFTP"""
        # ล้างข้อมูลเก่า
        for item in self.remote_tree.get_children():
            self.remote_tree.delete(item)
        
        # เชื่อมต่อ SFTP เพื่อดึงรายการไฟล์
        try:
            SFTP_HOST = self.current_sftp_profile['host']
            SFTP_USER = self.current_sftp_profile['username']
            SFTP_PASS = self.current_sftp_profile['password']
            SFTP_PORT = 22
            transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
            transport.connect(username=SFTP_USER, password=SFTP_PASS)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            files = sftp.listdir_attr(self.current_sftp_profile['remote_dir'])
            for file_attr in files:
                if not file_attr.filename.startswith('.'):  # ข้ามไฟล์ระบบ
                    size = file_attr.st_size / 1024  # KB
                    mtime = time.strftime('%Y-%m-%d %H:%M:%S', 
                                        time.localtime(file_attr.st_mtime))
                    self.remote_tree.insert("", "end", 
                                        values=(file_attr.filename, f"{size:.2f}", mtime))
            
            sftp.close()
            transport.close()
        except Exception as e:
            logger.error(f"❌ ไม่สามารถดึงรายการไฟล์จากเซิร์ฟเวอร์: {e}")
            messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์: {e}")

    def download_selected(self):
        """ดาวน์โหลดไฟล์ที่เลือกจากเซิร์ฟเวอร์"""
        selected_item = self.remote_tree.selection()
        if not selected_item:
            messagebox.showwarning("คำเตือน", "โปรดเลือกไฟล์ที่ต้องการดาวน์โหลด")
            return
        
        filename = self.remote_tree.item(selected_item)['values'][0]
        self.download_filename_var.set(filename)
        self.handle_download()

    def browse_folder(self):
        """เลือกโฟลเดอร์และรีเฟรชไฟล์"""
        folder = filedialog.askdirectory()
        if folder:
            self.watch_folder_var.set(folder)
            self.refresh_local_files()
class SftpProfileManager:
    def __init__(self, config_file="sftp_profiles.json"):
        self.config_file = config_file
        self.profiles = {}
        self.load_profiles()

    def load_profiles(self):
        """โหลดข้อมูลเซิร์ฟเวอร์จากไฟล์"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.profiles = json.load(f)
            except Exception as e:
                messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถโหลดไฟล์กำหนดค่า: {e}")
                self.profiles = {}
        else:
            # สร้างไฟล์ใหม่หากไม่มี
            messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถโหลดไฟล์กำหนดค่า: {e}")
            self.profiles = {
                "default": {
                    "host": "example.com",
                    "port": 22,
                    "username": "user",
                    "password": "",
                    "remote_dir": "/upload"
                }
            }
            self.save_profiles()

    def save_profiles(self):
        """บันทึกข้อมูลเซิร์ฟเวอร์ลงไฟล์"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.profiles, f, indent=4)
            return True
        except Exception as e:
            messagebox.showerror("ข้อผิดพลาด", f"ไม่สามารถบันทึกไฟล์กำหนดค่า: {e}")
            return False

    def add_profile(self, name, host, port, username, password, remote_dir):
        """เพิ่มโปรไฟล์ใหม่"""
        if name in self.profiles:
            return False, "มีชื่อโปรไฟล์นี้อยู่แล้ว"
        
        self.profiles[name] = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "remote_dir": remote_dir
        }
        self.save_profiles()
        return True, "เพิ่มโปรไฟล์สำเร็จ"

    def update_profile(self, name, host, port, username, password, remote_dir):
        """อัปเดตโปรไฟล์ที่มีอยู่"""
        if name not in self.profiles:
            return False, "ไม่พบโปรไฟล์ที่ต้องการอัปเดต"
        
        self.profiles[name] = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "remote_dir": remote_dir
        }
        self.save_profiles()
        return True, "อัปเดตโปรไฟล์สำเร็จ"

    def delete_profile(self, name):
        """ลบโปรไฟล์"""
        if name not in self.profiles:
            return False, "ไม่พบโปรไฟล์ที่ต้องการลบ"
        
        del self.profiles[name]
        self.save_profiles()
        return True, "ลบโปรไฟล์สำเร็จ"

    def get_profile(self, name):
        """ดึงข้อมูลโปรไฟล์"""
        return self.profiles.get(name, None)

    def list_profiles(self):
        """แสดงรายชื่อโปรไฟล์ทั้งหมด"""
        return list(self.profiles.keys())
class SftpProfileWindow(tk.Toplevel):
    def __init__(self, parent, profile_manager, on_profile_selected=None):
        super().__init__(parent)
        self.profile_manager = profile_manager
        self.on_profile_selected = on_profile_selected
        
        self.title("จัดการเซิร์ฟเวอร์ SFTP")
        self.geometry("600x500")
        
        # ตั้งค่าสไตล์
        style = ttk.Style()
        style.configure('Sftp.TFrame', background='#f0f0f0')
        style.configure('Sftp.TLabel', background='#f0f0f0', font=('Tahoma', 10))
        style.configure('Sftp.TButton', font=('Tahoma', 10))
        
        # ส่วนเลือกโปรไฟล์
        self._setup_profile_selection()
        
        # ส่วนแสดงรายละเอียดโปรไฟล์
        self._setup_profile_details()
        
        # ส่วนปุ่มควบคุม
        self._setup_control_buttons()
        
        # โหลดโปรไฟล์แรกเริ่ม
        self._load_profile_list()
    
    def _setup_profile_selection(self):
        """ตั้งค่าส่วนเลือกโปรไฟล์"""
        selection_frame = ttk.LabelFrame(self, text="เลือกเซิร์ฟเวอร์", style='Sftp.TFrame')
        selection_frame.pack(fill="x", padx=10, pady=5)
        
        # Combobox สำหรับเลือกโปรไฟล์
        ttk.Label(selection_frame, text="เซิร์ฟเวอร์:", style='Sftp.TLabel').pack(side="left", padx=5)
        self.profile_combobox = ttk.Combobox(selection_frame, state="readonly")
        self.profile_combobox.pack(side="left", fill="x", expand=True, padx=5)
        self.profile_combobox.bind("<<ComboboxSelected>>", self._on_profile_selected)
        
        # ปุ่มรีเฟรช
        btn_refresh = ttk.Button(
            selection_frame,
            text="รีเฟรช",
            command=self._load_profile_list,
            style='Sftp.TButton'
        )
        btn_refresh.pack(side="right", padx=5)
    
    def _setup_profile_details(self):
        """ตั้งค่าส่วนแสดงรายละเอียดโปรไฟล์"""
        details_frame = ttk.LabelFrame(self, text="รายละเอียดเซิร์ฟเวอร์", style='Sftp.TFrame')
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # ชื่อโปรไฟล์
        ttk.Label(details_frame, text="ชื่อโปรไฟล์:", style='Sftp.TLabel').grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.profile_name = ttk.Entry(details_frame, width=30)
        self.profile_name.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        # Host
        ttk.Label(details_frame, text="Host:", style='Sftp.TLabel').grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.host = ttk.Entry(details_frame, width=30)
        self.host.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        # Port
        ttk.Label(details_frame, text="Port:", style='Sftp.TLabel').grid(row=2, column=0, padx=5, pady=5, sticky='e')
        self.port = ttk.Entry(details_frame, width=10)
        self.port.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Username
        ttk.Label(details_frame, text="Username:", style='Sftp.TLabel').grid(row=3, column=0, padx=5, pady=5, sticky='e')
        self.username = ttk.Entry(details_frame, width=30)
        self.username.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        # Password
        ttk.Label(details_frame, text="Password:", style='Sftp.TLabel').grid(row=4, column=0, padx=5, pady=5, sticky='e')
        self.password = ttk.Entry(details_frame, width=30, show="*")
        self.password.grid(row=4, column=1, padx=5, pady=5, sticky='w')
        
        # Remote Directory
        ttk.Label(details_frame, text="โฟลเดอร์ปลายทาง:", style='Sftp.TLabel').grid(row=5, column=0, padx=5, pady=5, sticky='e')
        self.remote_dir = ttk.Entry(details_frame, width=30)
        self.remote_dir.grid(row=5, column=1, padx=5, pady=5, sticky='w')
        
        # ปุ่มทดสอบการเชื่อมต่อ
        btn_test = ttk.Button(
            details_frame,
            text="ทดสอบการเชื่อมต่อ",
            command=self._test_connection,
            style='Sftp.TButton'
        )
        btn_test.grid(row=6, column=1, pady=10, sticky='e')
    
    def _setup_control_buttons(self):
        """ตั้งค่าส่วนปุ่มควบคุม"""
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        # ปุ่มเลือก
        self.btn_select = ttk.Button(
            button_frame,
            text="เลือกเซิร์ฟเวอร์นี้",
            command=self._select_current_profile,
            style='Sftp.TButton',
            state='disabled'
        )
        self.btn_select.pack(side="right", padx=5)
        
        # ปุ่มเพิ่ม
        btn_add = ttk.Button(
            button_frame,
            text="เพิ่มใหม่",
            command=self._add_profile,
            style='Sftp.TButton'
        )
        btn_add.pack(side="left", padx=5)
        
        # ปุ่มอัปเดต
        self.btn_update = ttk.Button(
            button_frame,
            text="อัปเดต",
            command=self._update_profile,
            style='Sftp.TButton',
            state='disabled'
        )
        self.btn_update.pack(side="left", padx=5)
        
        # ปุ่มลบ
        self.btn_delete = ttk.Button(
            button_frame,
            text="ลบ",
            command=self._delete_profile,
            style='Sftp.TButton',
            state='disabled'
        )
        self.btn_delete.pack(side="left", padx=5)
    
    def _load_profile_list(self):
        """โหลดรายการโปรไฟล์ลงใน Combobox"""
        profiles = self.profile_manager.list_profiles()
        self.profile_combobox['values'] = profiles
        if profiles:
            self.profile_combobox.current(0)
            self._on_profile_selected()
    
    def _on_profile_selected(self, event=None):
        """เมื่อเลือกโปรไฟล์จาก Combobox"""
        selected = self.profile_combobox.get()
        if not selected:
            return
        
        profile = self.profile_manager.get_profile(selected)
        if profile:
            self.profile_name.delete(0, tk.END)
            self.profile_name.insert(0, selected)
            
            self.host.delete(0, tk.END)
            self.host.insert(0, profile.get('host', ''))
            
            self.port.delete(0, tk.END)
            self.port.insert(0, str(profile.get('port', 22)))
            
            self.username.delete(0, tk.END)
            self.username.insert(0, profile.get('username', ''))
            
            self.password.delete(0, tk.END)
            self.password.insert(0, profile.get('password', ''))
            
            self.remote_dir.delete(0, tk.END)
            self.remote_dir.insert(0, profile.get('remote_dir', '/'))
            
            # เปิดใช้งานปุ่มต่างๆ
            self.btn_select.config(state='normal')
            self.btn_update.config(state='normal')
            self.btn_delete.config(state='normal')
    
    def _add_profile(self):
        """เพิ่มโปรไฟล์ใหม่"""
        # ตรวจสอบข้อมูล
        name = self.profile_name.get().strip()
        host = self.host.get().strip()
        port = self.port.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        remote_dir = self.remote_dir.get().strip()
        
        if not all([name, host, port, username, remote_dir]):
            messagebox.showwarning("คำเตือน", "กรุณากรอกข้อมูลให้ครบถ้วน")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("ข้อผิดพลาด", "Port ต้องเป็นตัวเลข")
            return
        
        # เพิ่มโปรไฟล์
        success, msg = self.profile_manager.add_profile(
            name, host, port, username, password, remote_dir
        )
        
        if success:
            messagebox.showinfo("สำเร็จ", msg)
            self._load_profile_list()
        else:
            messagebox.showerror("ข้อผิดพลาด", msg)
    
    def _update_profile(self):
        """อัปเดตโปรไฟล์"""
        # ตรวจสอบข้อมูล
        name = self.profile_name.get().strip()
        host = self.host.get().strip()
        port = self.port.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        remote_dir = self.remote_dir.get().strip()
        
        if not all([name, host, port, username, remote_dir]):
            messagebox.showwarning("คำเตือน", "กรุณากรอกข้อมูลให้ครบถ้วน")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("ข้อผิดพลาด", "Port ต้องเป็นตัวเลข")
            return
        
        # อัปเดตโปรไฟล์
        success, msg = self.profile_manager.update_profile(
            name, host, port, username, password, remote_dir
        )
        
        if success:
            messagebox.showinfo("สำเร็จ", msg)
            self._load_profile_list()
        else:
            messagebox.showerror("ข้อผิดพลาด", msg)
    
    def _delete_profile(self):
        """ลบโปรไฟล์"""
        name = self.profile_name.get().strip()
        if not name:
            return
        
        if not messagebox.askyesno("ยืนยัน", f"ต้องการลบโปรไฟล์ '{name}' จริงหรือไม่?"):
            return
        
        success, msg = self.profile_manager.delete_profile(name)
        if success:
            messagebox.showinfo("สำเร็จ", msg)
            self._clear_fields()
            self._load_profile_list()
        else:
            messagebox.showerror("ข้อผิดพลาด", msg)
    
    def _clear_fields(self):
        """ล้างข้อมูลในฟิลด์ทั้งหมด"""
        self.profile_name.delete(0, tk.END)
        self.host.delete(0, tk.END)
        self.port.delete(0, tk.END)
        self.username.delete(0, tk.END)
        self.password.delete(0, tk.END)
        self.remote_dir.delete(0, tk.END)
        
        # ปิดใช้งานปุ่มต่างๆ
        self.btn_select.config(state='disabled')
        self.btn_update.config(state='disabled')
        self.btn_delete.config(state='disabled')
    
    def _test_connection(self):
        """ทดสอบการเชื่อมต่อ SFTP"""
        host = self.host.get().strip()
        port = self.port.get().strip()
        username = self.username.get().strip()
        password = self.password.get()
        
        if not all([host, port, username]):
            messagebox.showwarning("คำเตือน", "กรุณากรอก Host, Port และ Username")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("ข้อผิดพลาด", "Port ต้องเป็นตัวเลข")
            return
        
        try:
            import paramiko
            transport = paramiko.Transport((host, port))
            transport.connect(username=username, password=password)
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.close()
            transport.close()
            
            messagebox.showinfo("สำเร็จ", "เชื่อมต่อเซิร์ฟเวอร์ SFTP สำเร็จ")
        except Exception as e:
            messagebox.showerror("ข้อผิดพลาด", f"เชื่อมต่อเซิร์ฟเวอร์ SFTP ไม่สำเร็จ:\n{str(e)}")
    
    def _select_current_profile(self):
        """เลือกโปรไฟล์ปัจจุบันเพื่อใช้งาน"""
        if self.on_profile_selected:
            profile_name = self.profile_name.get().strip()
            profile = self.profile_manager.get_profile(profile_name)
            if profile:
                self.on_profile_selected(profile)
                self.destroy()
# ======== Start main application =========
if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    
    # กำหนดการทำงานเมื่อปิดหน้าต่าง
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    root.mainloop()