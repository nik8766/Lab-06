import requests
import hashlib
import re
import os
import subprocess

file_url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'


def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    
    resp_msg = requests.get(file_url)
    # Hint: See example code in lab instructions entitled "Extracting Text from a Response Message Body"
    
    if resp_msg.status_code == requests.codes.ok:
        
        File = resp_msg.text 
        regex_sha256_pattern = r"^Expected SHA-256\s*:\s*([a-fA-F0-9]+)$"
        pattern = re.search(regex_sha256_pattern, File)
    # Hint: Use str class methods, str slicing, and/or regex to extract the expected SHA-256 value from the text 

        if pattern:
            return pattern.group(1)
            
        return None 

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # TODO: Step 2
    resp_msg = requests.get(file_url)

    if resp_msg.status_code == requests.codes.ok:
        #file_content = resp_msg.content
        return resp_msg.content
    

    
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
        return None

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
    resp_msg = requests.get(file_url)
    # Hint: See example code in lab instructions entitled "Computing the Hash Value of a Response Message Body"
    #if resp_msg.status_code == requests.codes.ok:
    IMAGE_hash = hashlib.sha256(installer_data).hexdigest()

    if installer_data and expected_sha256 == IMAGE_hash:
        #file_content = resp_msg.content
        return IMAGE_hash
    return None

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    resp_msg = requests.get(file_url +  'vlc-3.0.17.4-win64.exe')


    
    if resp_msg.status_code == requests.codes.ok:
        installer_data = resp_msg.content
        expected_hash = get_expected_sha256()


    if installer_data and expected_hash == installer_ok:
        temp_folder  = os.getenv('Temp')
        INSTALL_PATH = os.path.join(temp_folder, 'vls_installer.exe')

        with open(INSTALL_PATH, 'wb') as file: 
            file.write(installer_data)
    
    # Hint: See example code in lab instructions entitled "Downloading a Binary File"
            return installer_data
    return None

def run_installer(installer_path):
    """Silently runs the VLC installer.

    
    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
   # installer_path = r'C:\temp\vlc-3.0.17.4-win64.exe'
    subprocess.run([installer_path, '/L=1033', '/S'])


    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    return
    
def delete_installer(installer_path):
    # TODO: Step 6

    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """

    if os.path.exists(installer_path):
        os.remove(installer_path)
    return None

if __name__ == '__main__':
    main()