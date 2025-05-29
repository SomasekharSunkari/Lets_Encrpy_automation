import datetime
import logging
import os
import tempfile
import subprocess
import json

from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient

def main(mytimer: dict) -> None:
    # Get configuration from environment variables
    # domain = os.environ["DOMAIN_NAME"]
    # email = os.environ["EMAIL"]
    # keyvault_url = os.environ["KEYVAULT_URL"]
    domain = "devcheck1.somasekhar.xyz"
    email = "sekhar@somasekhar.xyz"
    keyvault_url = "https://sekhar-keyvault.vault.azure.net/"
    
    logging.info(f"Starting certificate generation for {domain}")
    
    # Create temporary directory for certbot files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Run certbot to generate certificate
        try:
            cmd = [
                "certbot", "certonly", "--standalone", "--preferred-challenges", "http",
                "--agree-tos", "--email", email, "-d", domain,
                "--config-dir", temp_dir, "--work-dir", temp_dir, "--logs-dir", temp_dir,
                "--non-interactive"
            ]
            
            # This will use HTTP-01 challenge with standalone webserver
            result = subprocess.run(cmd, capture_output=True, text=True)
            logging.info(f"Certbot output: {result.stdout}")
            
            if result.returncode != 0:
                logging.error(f"Certbot error: {result.stderr}")
                return
            
            # Read certificate files
            cert_path = f"{temp_dir}/live/{domain}/fullchain.pem"
            key_path = f"{temp_dir}/live/{domain}/privkey.pem"
            
            with open(cert_path, "r") as cert_file:
                cert_content = cert_file.read()
            
            with open(key_path, "r") as key_file:
                key_content = key_file.read()
            
            # Store in Key Vault
            credential = DefaultAzureCredential()
            
            # Store certificate
            cert_client = CertificateClient(vault_url=keyvault_url, credential=credential)
            secret_client = SecretClient(vault_url=keyvault_url, credential=credential)
            
            # Store as secret (PEM format)
            cert_name = f"{domain.replace('.', '-')}-cert"
            secret_client.set_secret(cert_name, cert_content)
            
            key_name = f"{domain.replace('.', '-')}-key"
            secret_client.set_secret(key_name, key_content)
            
            # Store metadata
            metadata = {
                "domain": domain,
                "created": datetime.datetime.utcnow().isoformat(),
                "expires": (datetime.datetime.utcnow() + datetime.timedelta(days=90)).isoformat()
            }
            
            secret_client.set_secret(f"{domain.replace('.', '-')}-metadata", json.dumps(metadata))
            
            logging.info(f"Successfully stored certificate for {domain} in Key Vault")
            
        except Exception as e:
            logging.error(f"Error generating certificate: {str(e)}")
if __name__ == "__main__":
    main({})
