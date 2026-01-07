//deshifrlaydi
#!/usr/bin/env python3
import base64
import binascii
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path):
    with open(path, "rb") as f:
        key_data = f.read()
    # 🔥 Parolsiz yuklash (password=None)
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
    return private_key

def try_decode_ciphertext(text):
    text = text.strip()
    # 1) base64
    try:
        decoded = base64.b64decode(text, validate=True)
        return decoded
    except (binascii.Error, ValueError):
        pass
    # 2) hex
    try:
        decoded = bytes.fromhex(text)
        return decoded
    except ValueError:
        pass
    raise ValueError("Matnni base64 yoki hex formatida kiriting.")

def decrypt_rsa(cipher_bytes, private_key):
    plaintext_bytes = private_key.decrypt(
        cipher_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return plaintext_bytes.hex()

def main():
    print("=== RSA DESHIFRLASH (private.pem, parolsiz) ===")
    private_path = "private.pem"

    try:
        key = load_private_key(private_path)
    except FileNotFoundError:
        print(f"❌ Fayl topilmadi: {private_path}")
        return
    except Exception as e:
        print(f"❌ Private keyni yuklashda xatolik: {e}")
        return

    encrypted_input = input("Shifrlangan matnni kiriting (Base64 yoki hex): ").strip()
    try:
        cipher_bytes = try_decode_ciphertext(encrypted_input)
    except ValueError as e:
        print(f"❌ {e}")
        return

    try:
        original = decrypt_rsa(cipher_bytes, key)
        print("\n🔓 Deshifrlangan matn (original):")
        print(original)
    except Exception as e:
        print(f"❌ Deshifrlashda xatolik yuz berdi: {e}")

if __name__ == "__main__":
    main()
