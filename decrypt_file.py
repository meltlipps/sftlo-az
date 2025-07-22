from cryptography.fernet import Fernet

def load_key(key_path="secret.key"):
    return open(key_path, "rb").read()

def decrypt_file(encrypted_path, output_path, key):
    fernet = Fernet(key)
    with open(encrypted_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_path, "wb") as out_file:
        out_file.write(decrypted_data)

if __name__ == "__main__":
    key = load_key("secret.key")

    # เปลี่ยนตามชื่อไฟล์ของคุณ
    decrypt_file(
        encrypted_path="downloaded/COOP_ALProject0_1.0.0.19.app.enc",
        output_path="decrypted/COOP_ALProject0_1.0.0.19.app",
        key=key
    )

    print("✅ ถอดรหัสเสร็จเรียบร้อย")
