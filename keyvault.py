from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.identity import InteractiveBrowserCredential
import os
# Define Azure Key Vault Information
VAULT_URL = "https://<yours>.vault.azure.net/"  # Replace with your Key Vault URL

def main():
    # Step 1: Authenticate with Azure
    try:

        os.environ.setdefault('AZURE_TENANT_ID', '<tenant_id>')  
        os.environ.setdefault('AZURE_CLIENT_ID', '<clientid>')  
        os.environ.setdefault('AZURE_CLIENT_SECRET', '<client_secret_value not id>')  

        # Use DefaultAzureCredential for authentication
        # It works with Azure CLI login, Managed Identity, or Environment Variables
        credential = DefaultAzureCredential()
        # Step 2: Initialize the Secret Client
        secret_client = SecretClient(vault_url=VAULT_URL, credential=credential)
        print("Connected to Azure Key Vault.")

        # Step 3: Store a Secret
        secret_name = "mySecretPassword"
        secret_value = "SuperSecurePassword123!"

        print(f"Storing secret '{secret_name}'...")
        secret_client.set_secret(secret_name, secret_value)
        print("Secret stored successfully!")

        # Step 4: Retrieve a Secret
        print(f"Retrieving secret '{secret_name}'...")
        retrieved_secret = secret_client.get_secret(secret_name)
        print(f"Retrieved secret value: {retrieved_secret.value}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
