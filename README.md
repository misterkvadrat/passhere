# PassHere

A secure, portable local password manager written in Python. Designed for physical portability and data privacy without cloud dependencies.

## 🔒 Key Features
- **Encryption**: AES-based encryption (Fernet) with PBKDF2 key derivation.
- **Portability**: Compiles to a single `.exe` file; runs without Python installed.
- **Privacy**: Zero-knowledge architecture (master password never stored); salted hashing.
- **Offline**: All data stored locally in an encrypted vault file.

## 🚀 Quick Start
1. Clone: `git clone https://github.com/misterkvadrat/passhere.git`
2. Install deps: `pip install -r requirements.txt`
3. Run: `python passhere.py`

## 🛠 Tech Stack
Python, Cryptography, PyInstaller, Git.
