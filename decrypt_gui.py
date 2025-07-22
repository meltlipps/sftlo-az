import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os

# โหลดคีย์
def load_key(key_path="secret.key"):
    if not os.path.exists(key_path):
        messagebox.showerror("❌ ไม่พบ Key", f"ไม่พบไฟล์: {key_path}")
        return None
    return open(key_path, "rb").read()

# ถอดรหัสไฟล์
def decrypt_file(filepath, key):
    try:
        fernet = Fernet(key)
        with open(filepath, "rb") as enc_file:
            encrypted = enc_file.read()
        decrypted = fernet.decrypt(encrypted)

        if filepath.endswith(".enc"):
            output_path = filepath[:-4]  # ตัด ".enc"
        else:
            output_path = filepath + ".dec"

        with open(output_path, "wb") as dec_file:
            dec_file.write(decrypted)

        return output_path
    except Exception as e:
        return str(e)

# เลือกไฟล์ .enc
def choose_file():
    file_path = filedialog.askopenfilename(title="เลือกไฟล์ .enc", filetypes=[("Encrypted files", "*.enc")])
    if file_path:
        key = load_key()
        if not key:
            return
        result = decrypt_file(file_path, key)
        if os.path.exists(result):
            status_var.set(f"✅ ถอดรหัสแล้ว: {os.path.basename(result)}")
            messagebox.showinfo("สำเร็จ", f"✅ ถอดรหัสไฟล์แล้ว:\n{os.path.basename(result)}")
        else:
            status_var.set("❌ ถอดรหัสล้มเหลว")
            messagebox.showerror("ล้มเหลว", f"❌ ถอดรหัสไม่สำเร็จ:\n{result}")

# สร้างหน้าต่าง
window = tk.Tk()
window.title("🛡️ Decrypt .enc File")
window.geometry("400x200")
window.resizable(False, False)

style = ttk.Style(window)
style.configure("TButton", font=("Segoe UI", 11), padding=10)
style.configure("TLabel", font=("Segoe UI", 11))

# Label ด้านบน
label = ttk.Label(window, text="📂 เลือกไฟล์ .enc ที่ต้องการถอดรหัส")
label.pack(pady=(20, 10))

# ปุ่มเลือกไฟล์
select_button = ttk.Button(window, text="เลือกไฟล์ .enc", command=choose_file)
select_button.pack(pady=10)

# สถานะ
status_var = tk.StringVar()
status_label = ttk.Label(window, textvariable=status_var, foreground="green")
status_label.pack(pady=(10, 5))

# Run main loop
window.mainloop()
