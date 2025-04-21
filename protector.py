import os
import hashlib
import psutil
import requests
import pyexiv2
import win32com.client

# List of known bad hashes (you can update this list)
known_bad_hashes = [
    'd41d8cd98f00b204e9800998ecf8427e',  # Example malicious hash
    # Add more hashes here...
]

# Your VirusTotal API key
VIRUSTOTAL_API_KEY = 'dcbf99895bb94c725cb7d5546763387f4877cf892d96a801b97151f5d0dac530'


def monitor_processes():
    """Monitor processes and flag suspicious ones."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            print(f"Process: {proc.info['name']} with PID: {proc.info['pid']}")
            # Check for suspicious processes (e.g., 'evil.exe')
            if 'evil.exe' in proc.info['name'].lower():
                print(f"⚠️ Suspicious process detected: {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def check_file_size(file_path):
    """Check file size and flag if suspicious."""
    try:
        file_size = os.path.getsize(file_path)
        print(f"File Size: {file_size} bytes")
        if file_size > 1000000:  # Files larger than 1MB
            print(f"⚠️ Suspicious file size detected: {file_path}")
    except Exception as e:
        print(f"Error checking file size: {e}")


def check_file_hash(file_path):
    """Check file hash against known bad hashes."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        file_hash = sha256_hash.hexdigest()
        print(f"File Hash: {file_hash}")

        if file_hash in known_bad_hashes:
            print("⚠️ Malicious file detected based on hash!")
    except Exception as e:
        print(f"Error checking file hash: {e}")


def analyze_metadata(file_path):
    """Extract and analyze file metadata."""
    try:
        metadata = pyexiv2.ImageMetadata(file_path)
        metadata.read()
        print("Metadata:")
        for key in metadata.exif_keys:
            print(f"{key}: {metadata[key]}")
    except Exception as e:
        print(f"Error reading metadata: {e}")


def check_digital_signature(file_path):
    """Check if the file has a valid digital signature (Windows only)."""
    try:
        signer = win32com.client.Dispatch("Microsoft.Signer")
        result = signer.VerifySignature(file_path)
        print(f"Digital signature status: {result}")
        if result == "Not Signed":
            print("⚠️ The file does not have a valid digital signature!")
        elif result == "Signed":
            print("The file has a valid signature.")
    except Exception as e:
        print(f"Error checking digital signature: {e}")


def check_file_with_virustotal(file_hash):
    """Query VirusTotal for the file's hash."""
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': file_hash
    }
    try:
        response = requests.get(url, params=params)
        json_response = response.json()

        if json_response['response_code'] == 1:
            print(f"VirusTotal report: {json_response['positives']} AV engines flagged this file.")
        else:
            print("File is clean or not found in VirusTotal.")
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")


def scan_downloaded_file(file_path):
    """Perform all checks on the downloaded file."""
    print(f"\n🔍 Scanning file: {file_path}")

    # Check if file name is 'evil.exe' and delete it
    if os.path.basename(file_path).lower() == 'evil.exe':
        print("⚠️ Suspicious file name detected: 'evil.exe'")
        try:
            os.remove(file_path)
            print("🗑️ The file has been deleted for safety.")
        except Exception as e:
            print(f"Error deleting suspicious file: {e}")
        return  # Stop further checks

    # Monitor for suspicious processes
    monitor_processes()

    # Check file size
    check_file_size(file_path)

    # Check file hash against known malicious hashes
    check_file_hash(file_path)

    # Analyze file metadata (for images)
    analyze_metadata(file_path)

    # Check digital signature (Windows)
    check_digital_signature(file_path)

    # Check file hash with VirusTotal
    try:
        file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
        check_file_with_virustotal(file_hash)
    except Exception as e:
        print(f"Error calculating file hash for VirusTotal: {e}")


if __name__ == '__main__':
    # Example usage
    downloaded_file_path = 'path/to/suspect_file.exe'  # Replace with actual file path
    scan_downloaded_file(downloaded_file_path)
