# Encryption-Decyrption Project
Encryption and decryption Project using python

Terminal Tool Documentation

# Table of Contents

- Overview
- Features
- Security Details
- Installation
- Dependencies
- Usage
- Code Documentation
- Steps to run python commands:
- Steps to execute the docker image:
- Examples

# OverView:
The Terminal Encryption Tool is a command-line application that provides secure file and directory encryption using AES-256 encryption. It supports both file and directory encryption/decryption, with a unique key management system that incorporates date-based validation. Creating a tool that should encyrpt and decrypt the files. When we encrypt the files we need to  generate a 7 letter code which includes letters, special characters, and NN and MM modules. When we decrypt the file, if there is NN or MM modules in the 7 letter code, the tool should dynamically change the NN or MM to the date or month of the file decryption. (ex: encyrption key : compaNN, then if the date of decrypiton is 20th of October, the decryption key will be : compa20). If there is any special character in the encyrption key, the decryption key should invert the NN or MM module (encryption key : comp/NN, then if the date of decryption is 20th of October, the decryption key should be : comp/02).


# Features

- AES-256 encryption for files and directories
- User-specific key management
- Date-based key validation
- Support for both single file and recursive directory encryption
- Cross-platform compatibility (Windows, Linux, macOS)
- Metadata embedding for enhanced security


# Security Details

- Encryption Algorithm: AES-256 in CBC mode
- Key Derivation: PBKDF2 with SHA-256
- Initialization Vector: Random 16-byte IV for each encryption
- Padding: PKCS7 padding
- Metadata: 8-byte metadata embedded in encrypted files


# Prerequisites.
- Python 3.7 or higher
- pip (Python package installer)
- Docker desktop for windows and macos for docker image.
# Installation
- Install the required dependencies using pip:

  `pip install cryptography pwinput`

or elsecreate a virtual environment and install dependencies:
    bash
    ```python -m venv venv
    source venv/bin/activate
    pip install cryptography pwinput```


# Steps to run python commands:

  Run the below python command using encryption_tool.py script to encrypt a file:

`python encryption_tool.py encrypt path/to/file`

Run the below python command using encryption_tool.py script to decrypt a file:

`python encryption_tool.py decrypt path/to/file.enc`

Run the below python command using encryption_tool.py script to encrypt a directory:

`python encryption_tool.py encrypt path/to/directory `

Run the below python command using encryption_tool.py script to decrypt a directory:

`python encryption_tool.py decrypt path/to/directory_enc`



# Secret Key Format

The key should be seven alphanumeric characters. You can include special date placeholders:
MM: Will be replaced with the current month
NN: Will be replaced with the current date
if there are any special characters in the secret key, it will reverse the digits of the MM and NN.

# Examples:

- Key: @3jcfA5 - Simple alphanumeric key
- Key: cjnsMMa - Uses current month
- Key: @#$%!MM - Uses reversed current month
- Key: NN()jjc - Uses current date

# Steps to execute the docker image:
To build the docker image

`docker build -t imagename . `

To run the docker image when we want to encrypt the file:

`docker run -it -v <path of the file>:/mnt <image name>  encrypt /mnt/<filename>`

To run the docker image when we want to decrypt the file: 

`docker run -it -v <path of the file>:/mnt <image name>  decrypt /mnt/<filename.enc>`
To run the docker image when we want to encrypt and decrypt the folder:

`docker run -it -v <path of the folder>:/mnt <image name> encrypt /mnt/<foldername>`
To run the docker image when we want to encrypt and decrypt the folder:

`docker run -it -v <path of the file>:/mnt <image name>  decrypt /mnt/<foldername_enc>`







