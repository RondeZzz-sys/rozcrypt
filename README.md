# rozcrypt – ChaCha20 File Encryptor for Windows

**rozcrypt** is a lightweight, portable file encryption utility built with pure C and WinAPI. It provides a secure way to protect your files using the **ChaCha20** stream cipher, featuring a modern dark-themed "neon" interface.

---

## ✨ Technical Specifications

- 🔒 **Core Cipher**: ChaCha20 (20 rounds) with a 256-bit key.
- 🔑 **Key Derivation**: SHA-256 hashing for password-to-key transformation.
- 🛡️ **Integrity Control**: HMAC-SHA256 ensures the file hasn't been modified or corrupted.
- 🎲 **Unique IV**: Each file uses a random 12-byte nonce generated via `CryptGenRandom`.
- 🧹 **Privacy Focused**: 100% offline. No telemetry, no background connections, no data collection.
- 🎨 **Sleek UI**: Dark mode GUI with real-time "Block Authentication" visual feedback and progress tracking.

---

## 🚀 How to Use

1. **Run** `rozcrypt.exe`.
2. **Enter your password** in the "ENCRYPTION KEY" field.
3. **Drag and drop** files directly into the program window.
   - Files **without** `.rozcrypt` extension will be **Encrypted**.
   - Files **with** `.rozcrypt` extension will be **Decrypted**.
4. The program creates a new file and leaves the original untouched for safety.

> ⚠️ **IMPORTANT:** There is no "Forgot Password" button. If the key is lost, the data is unrecoverable due to the nature of ChaCha20 encryption.

---

## 🔧 Compilation

The project is a single-file C source code and requires only standard Windows libraries.

**Compiler requirements:**
- MSVC (cl.exe) or MinGW (gcc).
- Linked libraries: `user32.lib`, `gdi32.lib`, `advapi32.lib`, `shell32.lib`, `comctl32.lib`, `uxtheme.lib`.

**MSVC Command line:**
`cl.exe /O2 /MT /Fe:rozcrypt.exe main.c user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib uxtheme.lib /link /SUBSYSTEM:WINDOWS`

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.  
See the `LICENSE` file for full details.