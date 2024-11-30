from cryptography.fernet import Fernet

# Provided encryption key and encrypted text
key = b"V9KQCixm-xteMA96VhVFww9IOw0q8kZdLieWlJ6ATUY="
encrypted_text = b"gAAAAABnJwoUk3c3L83W6SlK8TTjIXCxmrqf0NFYBixNtvvE3t5fnV5_IzlD-0NTDT7zHlxKK_XocFavOtdeE9CfWZ43CZDd5Q=="

# Initialize Fernet with the provided key
fernet = Fernet(key)

# Decrypt the encrypted text
decrypted_message = fernet.decrypt(encrypted_text).decode()
print(f"Decrypted message: {decrypted_message}")
