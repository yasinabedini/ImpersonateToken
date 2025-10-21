# Impersonate TrustedInstaller Token (C++)

A minimal C++ proof-of-concept demonstrating how to impersonate the **TrustedInstaller** security context in Windows, allowing elevated access to protected system resources.  
This code starts the `TrustedInstaller` service if it’s not already running, retrieves its process token, duplicates it, and finally impersonates it on the current thread.

⚠️ **Disclaimer:**  
This project is for **educational and security research purposes only.**  
Running code under the `TrustedInstaller` context grants full system-level privileges which can modify or delete protected files. Misuse may damage your system.

---

## 🧩 Overview

Windows protects system files and registry keys with the `TrustedInstaller` account to prevent accidental or unauthorized modification.  
This tool demonstrates how to:
1. Start the `TrustedInstaller` service programmatically.
2. Locate its running process.
3. Open and duplicate its token.
4. Impersonate the token to temporarily gain its privileges.

---

## ⚙️ Build

### Requirements
- Windows 10 or later (x64)
- Visual Studio / MSVC toolchain
- Administrator privileges
- C++17 or newer

### Compilation
```bash
cl /EHsc /W4 /FeImpersonateTI.exe ImpersonateTI.cpp
