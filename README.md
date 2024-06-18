# EncryptEase

EncryptEase is a simple CLI app for file encryption and decryption, designed to securely handle one or multiple files simultaneously. It utilizes AES-GCM for encryption and decryption operations and employs the Argon2d key derivation algorithm for secure key generation.

## Features
- **AES-GCM Encryption**: Ensures confidentiality and integrity of encrypted data.
- **Multiple File Support**: Encrypt or decrypt one or multiple files in a single operation.
- **Argon2d Key Derivation**: Securely derives encryption keys from passwords or passphrases.
- **File Extension**: Encrypted files end with *.enc* as an extension.
- **Cross-Platform**: Compatible with Windows, macOS, and Linux.

## Usage

1. **Encrypting files**

    ```bash
    EncryptEase -e example_file ...example_fileN
    ```

2. **Decrypting files**

    ```bash
    EncryptEase -d example_file.enc ...example_fileN.enc
    ```

## Installation

To use EncryptEase, follow these steps:

1. **Clone the repository**

    ```bash
    git clone https://github.com/ShuaibKhan786/EncryptEase.git
    ```

2. **In the root directory**

    For macOS and Linux:
    
    - First change the file permission of the *script.sh* file
    
        ```bash
        chmod +x script.sh
        ```
    
    - Run the bash script with options:
    
        - For compiling and installing, use:
        
            ```bash
            ./script.sh -build
            ```
        
        - For installing precompiled binaries, use:
        
            ```bash
            ./script.sh -prebuild
            ```
        
        - For upgrading to a newer version, use:
        
            ```bash
            ./script.sh -upgrade
            ```
    
    - Finally, verify the installation by running:
    
        ```bash
        EncryptEase
        ```

    For Windows:
    
    - Support for Windows is coming soon.

## License

This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).

