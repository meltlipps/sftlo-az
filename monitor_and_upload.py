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

# ======== โหลด ENV =========
load_dotenv(dotenv_path="config.env")
SFTP_HOST = os.getenv("SFTP_HOST")
SFTP_PORT = int(os.getenv("SFTP_PORT", 22))
SFTP_USER = os.getenv("SFTP_USER")
SFTP_PASS = os.getenv("SFTP_PASS")
REMOTE_DIR = "/C:/Users/boat_/sftp-files"
WATCH_FOLDER = "C:/Users/Boat_/Downloads/watch_folder"
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = os.getenv("AZURE_CONTAINER_NAME")
assert AZURE_CONNECTION_STRING is not None, "❌ Missing AZURE_CONNECTION_STRING"
assert AZURE_CONTAINER_NAME is not None, "❌ Missing AZURE_CONTAINER_NAME"

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
##
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
                transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
                transport.connect(username=SFTP_USER, password=SFTP_PASS)
                sftp = paramiko.SFTPClient.from_transport(transport)

                if not os.path.exists(encrypted_path):
                    logger.error(f"[ERROR] ไฟล์เข้ารหัสหายไป: {encrypted_path}")
                    return

                remote_path = os.path.join(REMOTE_DIR, encrypted_filename).replace("\\", "/")
                sftp.put(encrypted_path, remote_path)
                logger.info(f"✅ [SFTP] อัปโหลดสำเร็จ: {encrypted_filename}")

                sftp.close()
                transport.close()

                # 📤 Upload to Azure + log
                log_upload(encrypted_path)

            except Exception as e:
                logger.error(f"[ERROR] อัปโหลดล้มเหลว: {encrypted_filename} | {e}")
                logger.debug(f"[DEBUG] path: {encrypted_path}")

# ======== Start main watcher =========
if __name__ == "__main__":
    print(f"🟢 เริ่มตรวจสอบโฟลเดอร์: {WATCH_FOLDER}")
    logger.info("🎬 เริ่มระบบ Watch + Encryption + Upload")
    event_handler = UploadHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
