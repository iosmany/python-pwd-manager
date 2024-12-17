from Crypto.Cipher import AES
import base64
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


class PasswordManagerKeyProvider():

    @property
    def key(self):
        return self.load_or_generate_key()

    def load_or_generate_key(self):
        raise NotImplementedError()
        
    
class AzureKeyVaultProvider(PasswordManagerKeyProvider):

    def __init__(self):
        self._vault_url = "https://<yours>.vault.azure.net/"

    def load_or_generate_key(self):
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=self._vault_url, credential=credential)
        secret_name = "aes-key"
        try:
            secret = client.get_secret(secret_name)
            key = secret.value.encode('latin1')
            print(f"Key loaded from Azure Key Vault: {secret_name}")
        except:
            key = os.urandom(32)  # 32 bytes for AES-256
            client.set_secret(secret_name, key.decode('latin1'))
            print(f"New AES key generated and saved to Azure Key Vault: {secret_name}")

        return key

    
class EnviromentKeyProvider(PasswordManagerKeyProvider):

    def __init__(self):
        self._key = os.environ.get('AES_KEY')

    @property
    def key(self):
        return self._key

    def load_or_generate_key(self):
        if not self._key:
            raise ValueError("AES_KEY environment variable not set")
        return self._key
    
class FileKeyProvider(PasswordManagerKeyProvider):

    def __init__(self):
        self.key_file = "aes.key"

    def load_or_generate_key(self):
        # Key must be 16, 24, or 32 bytes for AES
        if not os.path.exists(self.key_file):
            key = os.urandom(32)  # 32 bytes for AES-256
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print(f"New AES key generated and saved to {self.key_file}")
        else:
            with open(self.key_file, 'rb') as f:
                key = f.read()
            print(f"Key loaded from {self.key_file}")
        return key


class PasswordManager:

    def __init__(self):
        self.key_provider = FileKeyProvider()

    def pad(self, s):
        # Pad the data to make it a multiple of 16 bytes
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    def unpad(self, s):
        # Remove padding from the data
        return s[:-ord(s[-1])]

    def encrypt_password(self, password):
        cipher = AES.new(self.key_provider.key, AES.MODE_CBC,  self.key_provider.key[:16])  # IV is the first 16 bytes of the key
        padded_password = self.pad(password)
        encrypted = cipher.encrypt(padded_password.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_password(self, encrypted_password):
        cipher = AES.new(self.key_provider.key, AES.MODE_CBC,  self.key_provider.key[:16])
        decoded_encrypted = base64.b64decode(encrypted_password)
        decrypted = cipher.decrypt(decoded_encrypted)
        return self.unpad(decrypted.decode())

# Example usage
if __name__ == "__main__":

    os.environ.setdefault('AES_KEY', 'ÁSB.ý6éêÆsÈr¹äVÛ@▲→¬$>Í►ÿ`{')

    manager = PasswordManager()

    # Encrypt a passwordiosma
    password = input("Enter the password to encrypt: ")
    encrypted_password = manager.encrypt_password(password)
    print(f"Encrypted Password: {encrypted_password}")

    # Decrypt the password
    decrypted_password = manager.decrypt_password(encrypted_password)
    print(f"Decrypted Password: {decrypted_password}")
