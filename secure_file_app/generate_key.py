from cryptography.fernet import Fernet

key = Fernet.generate_key()

with open("secret.key", "wb") as f:
    f.write(key)

print("Key generated and saved to secret.key")
