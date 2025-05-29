import subprocess
import os
import re
import datetime
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
import time
import ssl
import socket
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key, BestAvailableEncryption
from cryptography.hazmat.backends import default_backend
import base64

# Domain to get certificate for
domain = "devcheck2.somasekhar.xyz"
storage_account_name="checkingsll77"
container_name="$web"
# Azure Key Vault configuration
keyvault_name = "myeastuskeyvault"  # Replace with your Key Vault name
keyvault_url = f"https://{keyvault_name}.vault.azure.net/"

# Function to check if a valid certificate already exists
def check_certificate(domain):
    print(f"\n[INFO] Checking if a valid certificate already exists for {domain}...")
    try:
        # Create an SSL context
        context = ssl.create_default_context()
        
        print(f"[INFO] Attempting to connect to {domain}:443 to check certificate...")
        # Connect to the domain with SSL
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate
                cert = ssock.getpeercert()
                
                print(f"[INFO] Successfully retrieved certificate for {domain}")
                # Check expiration date
                expire_date_str = cert['notAfter']
                expire_date = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                current_date = datetime.datetime.now()
                
                # Calculate days until expiration
                days_until_expiration = (expire_date - current_date).days
                
                if days_until_expiration > 30:  # If certificate is valid for more than 30 days
                    print(f"[SUCCESS] A valid certificate for {domain} already exists.")
                    print(f"[INFO] Certificate expires in {days_until_expiration} days on {expire_date.strftime('%Y-%m-%d')}.")
                    return True
                else:
                    print(f"[WARNING] Certificate for {domain} will expire in {days_until_expiration} days.")
                    print(f"[INFO] Expiration date: {expire_date.strftime('%Y-%m-%d')}.")
                    return False
    except Exception as e:
        print(f"[ERROR] Error checking certificate: {str(e)}")
        print("[INFO] No valid certificate found or unable to connect. Proceeding with certificate request.")
        return False

# Function to create PFX file from certificate and private key
def create_pfx(cert_path, key_path, pfx_path, password=None):
    print(f"\n[INFO] Creating PFX file from certificate and private key...")
    print(f"[INFO] Certificate path: {cert_path}")
    print(f"[INFO] Private key path: {key_path}")
    print(f"[INFO] Target PFX path: {pfx_path}")
    
    try:
        # Read certificate and private key files
        print("[INFO] Reading certificate file...")
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        print("[INFO] Reading private key file...")
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read()
        
        # Load the private key
        print("[INFO] Loading private key...")
        private_key = load_pem_private_key(key_data, password=None, backend=default_backend())
        
        # Load the certificate
        print("[INFO] Loading certificate...")
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Create PKCS12/PFX
        print("[INFO] Creating PKCS12/PFX data...")
        encryption_msg = "without encryption" if not password else "with password encryption"
        print(f"[INFO] PFX will be created {encryption_msg}")
        
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=domain.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=None if not password else BestAvailableEncryption(password.encode())
        )
        
        # Write PFX to file
        print(f"[INFO] Writing PFX data to file: {pfx_path}")
        with open(pfx_path, 'wb') as pfx_file:
            pfx_file.write(pfx_data)
        
        print(f"[SUCCESS] PFX file created at {pfx_path}")
        return pfx_data
    except Exception as e:
        print(f"[ERROR] Error creating PFX file: {str(e)}")
        return None

# Function to store certificate in Azure Key Vault
def store_in_keyvault(pfx_data, domain, password=None):
    print(f"\n[INFO] Storing certificate in Azure Key Vault...")
    print(f"[INFO] Key Vault URL: {keyvault_url}")
    
    try:
        # Create Azure credential
        print("[INFO] Creating Azure credential...")
        credential = DefaultAzureCredential()
        
        # Create Certificate client
        print("[INFO] Creating Certificate client...")
        certificate_client = CertificateClient(vault_url=keyvault_url, credential=credential)
        
        # Convert PFX to base64 for storage
        print("[INFO] Converting PFX to base64...")
        pfx_base64 = base64.b64encode(pfx_data).decode()
        
        # Create certificate name (replace dots with hyphens)
        cert_name = f"{domain.replace('.', '-')}"
        print(f"[INFO] Certificate will be stored with name: {cert_name}")
        
        # Import certificate to Key Vault
        print(f"[INFO] Importing certificate to Key Vault...")
        imported_certificate = certificate_client.import_certificate(
            certificate_name=cert_name,
            certificate_bytes=pfx_data,
            password=password
        )
        
        print(f"[SUCCESS] Certificate for {domain} imported to Key Vault as {cert_name}")
        print(f"[INFO] Certificate ID: {imported_certificate.id}")
        print(f"[INFO] Certificate will expire on: {imported_certificate.properties.expires_on}")
        
        return True
    except Exception as e:
        print(f"[ERROR] Error storing in Key Vault: {str(e)}")
        return False

# Check if a valid certificate already exists
print("\n[INFO] Starting certificate verification and acquisition process...")
print(f"[INFO] Target domain: {domain}")
print(f"[INFO] Key Vault: {keyvault_name}")

# if check_certificate(domain):
#     print("[INFO] Skipping certificate request as a valid certificate already exists.")
#     exit(0)

# Azure Storage configuration
print("\n[INFO] Configuring Azure Storage for ACME challenge...")
print(f"[INFO] Storage account: {storage_account_name}")
print(f"[INFO] Container: {container_name}")

# First run certbot in manual mode to get the challenge
cmd = [
    "certbot", "certonly",
    "--manual",  # Use manual mode to get the challenge
    "--preferred-challenges", "http",
    "-d", domain,
    "--agree-tos",
    "--email", "sunkarisekhar36@gmail.com"
]

print("\n[INFO] Running certbot to get challenge details...")
print(f"[INFO] Command: {' '.join(cmd)}")

# Run certbot to get the challenge details
process = subprocess.Popen(
    cmd, 
    stdout=subprocess.PIPE, 
    stderr=subprocess.PIPE,
    stdin=subprocess.PIPE,
    universal_newlines=True,
    bufsize=1
)

# Variables to store challenge details
challenge_token = None
token_content = None
output_buffer = ""
output_lines = []
created_files = []  # Track created files for cleanup

print("[INFO] Waiting for certbot to provide challenge details...")

# Read from stdout line by line
while True:
    line = process.stdout.readline()
    if not line and process.poll() is not None:
        break
    
    output_lines.append(line)
    output_buffer += line
    print(line, end='')  # Print the line for debugging
    
    # Check if we have the complete challenge information
    if "make it available on your web server at this URL:" in output_buffer:
        print("[INFO] Challenge information detected in certbot output...")
        
        # Extract token from URL
        url_match = re.search(r'http://[^/]+/.well-known/acme-challenge/([A-Za-z0-9_-]+)', output_buffer)
        if url_match:
            challenge_token = url_match.group(1)
            print(f"[INFO] Found challenge token: {challenge_token}")
        
        # Extract content
        content_match = re.search(r'containing just this data:\s*\n\s*\n([A-Za-z0-9_.-]+)\s*\n', output_buffer)
        if content_match:
            token_content = content_match.group(1)
            print(f"[INFO] Found token content: {token_content}")
        
        # If we have both token and content, create the file
        if challenge_token and token_content:
            challenge_path = f".well-known/acme-challenge/{challenge_token}"
            
            print(f"\n[INFO] Extracted challenge details:")
            print(f"[INFO] Token: {challenge_token}")
            print(f"[INFO] Content: {token_content}")
            print(f"[INFO] Path: {challenge_path}")
            
            try:
                print("[INFO] Authenticating with Azure...")
                # Use DefaultAzureCredential for authentication
                credential = DefaultAzureCredential()
                blob_service_client = BlobServiceClient(
                    account_url=f"https://{storage_account_name}.blob.core.windows.net",
                    credential=credential
                )
                
                print(f"[INFO] Getting container client for {container_name}...")
                # Get container client for $web container
                container_client = blob_service_client.get_container_client(container_name)
                
                print(f"[INFO] Creating blob client for {challenge_path}...")
                # Create blob client for the challenge file
                blob_client = blob_service_client.get_blob_client(
                    container=container_name, 
                    blob=challenge_path
                )
                
                print("[INFO] Uploading challenge token content to blob...")
                # Upload token content to the challenge file
                blob_client.upload_blob(token_content, overwrite=True)
                print(f"[SUCCESS] Successfully uploaded challenge file to {challenge_path}")
                
                # Track the created file for cleanup
                created_files.append(challenge_path)
                
                # Wait a moment for the file to propagate
                print("[INFO] Waiting 10 seconds for the file to propagate...")
                for i in range(10, 0, -1):
                    print(f"[INFO] {i} seconds remaining...", end="\r")
                    time.sleep(1)
                print("[INFO] Wait complete.                ")
                
                # Continue with certbot verification
                print("[INFO] Continuing with certbot verification...")
                process.stdin.write("\n")
                process.stdin.flush()
                
                # Reset for potential additional challenges
                challenge_token = None
                token_content = None
                output_buffer = ""
                
            except Exception as e:
                print(f"[ERROR] Error working with Azure Storage: {str(e)}")
                process.terminate()
                exit(1)

# Read any remaining output
print("[INFO] Reading remaining certbot output...")
stdout, stderr = process.communicate()
if stdout:
    print(stdout)
if stderr:
    print(stderr)

# Clean up the challenge files regardless of success or failure
print("\n[INFO] Cleaning up challenge files...")
try:
    print("[INFO] Authenticating with Azure for cleanup...")
    credential = DefaultAzureCredential()
    blob_service_client = BlobServiceClient(
        account_url=f"https://{storage_account_name}.blob.core.windows.net",
        credential=credential
    )
    
    for file_path in created_files:
        try:
            print(f"[INFO] Deleting {file_path}...")
            blob_client = blob_service_client.get_blob_client(
                container=container_name, 
                blob=file_path
            )
            blob_client.delete_blob()
            print(f"[SUCCESS] Deleted {file_path}")
        except Exception as e:
            print(f"[ERROR] Error deleting {file_path}: {str(e)}")
    
    # Try to delete the .well-known/acme-challenge directory if it exists and is empty
    try:
        print("[INFO] Checking if .well-known/acme-challenge directory is empty...")
        # List all blobs with the prefix
        acme_challenge_prefix = ".well-known/acme-challenge/"
        blobs = blob_service_client.get_container_client(container_name).list_blobs(name_starts_with=acme_challenge_prefix)
        
        # Check if there are any blobs left in the directory
        remaining_blobs = list(blobs)
        if not remaining_blobs:
            print("[INFO] No blobs left in .well-known/acme-challenge/, attempting to delete directory marker...")
            # No blobs left, we can try to delete the directory marker if it exists
            directory_marker = blob_service_client.get_blob_client(
                container=container_name,
                blob=acme_challenge_prefix
            )
            try:
                directory_marker.delete_blob()
                print(f"[SUCCESS] Deleted directory marker for {acme_challenge_prefix}")
            except Exception:
                # Directory marker might not exist, which is fine
                print("[INFO] No directory marker found for acme-challenge (this is normal)")
            
            # Also try to delete the .well-known directory if it's empty
            print("[INFO] Checking if .well-known directory is empty...")
            well_known_prefix = ".well-known/"
            well_known_blobs = blob_service_client.get_container_client(container_name).list_blobs(name_starts_with=well_known_prefix)
            if not list(well_known_blobs):
                print("[INFO] No blobs left in .well-known/, attempting to delete directory marker...")
                well_known_marker = blob_service_client.get_blob_client(
                    container=container_name,
                    blob=well_known_prefix
                )
                try:
                    well_known_marker.delete_blob()
                    print(f"[SUCCESS] Deleted directory marker for {well_known_prefix}")
                except Exception:
                    # Directory marker might not exist, which is fine
                    print("[INFO] No directory marker found for .well-known (this is normal)")
    except Exception as e:
        print(f"[ERROR] Error cleaning up directories: {str(e)}")
        
except Exception as e:
    print(f"[ERROR] Error during cleanup: {str(e)}")

if process.returncode != 0:
    print(f"[ERROR] Certbot failed with return code {process.returncode}")
    print("[INFO] Full output:")
    for line in output_lines:
        print(line, end='')
    exit(process.returncode)
else:
    print("\n[SUCCESS] Certificate successfully obtained!")
    
    # Extract certificate paths from output
    cert_path = None
    key_path = None
    
    # Look for certificate paths in the output
    print("[INFO] Extracting certificate paths from certbot output...")
    for line in output_lines:
        if "Certificate is saved at:" in line:
            cert_path = line.split("Certificate is saved at:")[1].strip()
            print(f"[INFO] Found certificate path: {cert_path}")
        elif "Key is saved at:" in line:
            key_path = line.split("Key is saved at:")[1].strip()
            print(f"[INFO] Found private key path: {key_path}")
    
    # If we couldn't find the paths in the output, use the default paths
    if not cert_path or not key_path:
        print("[INFO] Certificate paths not found in output, using default paths...")
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    
    print(f"[INFO] Using certificate at: {cert_path}")
    print(f"[INFO] Using key at: {key_path}")
    
    # Create a temporary PFX file
    pfx_path = f"/tmp/{domain}.pfx"
    pfx_password = "TemporaryPassword123"  # You can generate a random password here
    print(f"[INFO] Will create temporary PFX file at: {pfx_path}")
    
    # Create PFX file
    pfx_data = create_pfx(cert_path, key_path, pfx_path, pfx_password)
    
    if pfx_data:
        # Store in Key Vault as a certificate (not a secret)
        if store_in_keyvault(pfx_data, domain, pfx_password):
            print(f"[SUCCESS] Certificate for {domain} successfully stored in Key Vault")
        else:
            print(f"[ERROR] Failed to store certificate in Key Vault")
        
        # Clean up temporary PFX file
        try:
            print(f"[INFO] Cleaning up temporary PFX file: {pfx_path}")
            os.remove(pfx_path)
            print(f"[SUCCESS] Temporary PFX file {pfx_path} removed")
        except Exception as e:
            print(f"[ERROR] Error removing temporary PFX file: {str(e)}")
    else:
        print("[ERROR] Failed to create PFX file")

print("\n[INFO] Certificate acquisition process complete.")
