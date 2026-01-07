//kalit yaratadi va uni shifrlab berdi
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PRIVATE_PEM = 'private.pem'
PUBLIC_PEM = 'public.pem'

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_PEM, 'wb') as f:
        f.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_PEM, 'wb') as f:
        f.write(pem_public)

    print("✅ RSA kalitlar yaratildi.")

def load_public_key():
    with open(PUBLIC_PEM, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

def encrypt_text(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

if __name__ == '__main__':
    # 1. Kalitlar mavjudligini tekshirish
    if not (os.path.exists(PRIVATE_PEM) and os.path.exists(PUBLIC_PEM)):
        print("🔑 Kalitlar topilmadi. Yaratilmoqda...")
        generate_keys()

    # 2. Matnni kiriting
    plaintext = input("Shifrlanadigan matnni kiriting: ")

    # 3. Public kalitni yuklab olish
    public_key = load_public_key()

    # 4. Matnni shifrlash
    encrypted_text = encrypt_text(plaintext, public_key)

    # 5. Natija
    print("\n🔒 Shifrlangan matn (base64):")
    print(encrypted_text)

