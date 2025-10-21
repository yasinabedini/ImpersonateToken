# Impersonate TrustedInstaller Token (C++)

A minimal C++ proof-of-concept demonstrating how to impersonate the **TrustedInstaller** security context in Windows, allowing elevated access to protected system resources.  
This code starts the `TrustedInstaller` service if it’s not already running, retrieves its process token, duplicates it, and finally impersonates it on the current thread.

---

## 🧩 Overview

Windows protects system files and registry keys with the `TrustedInstaller` account to prevent accidental or unauthorized modification.  
This tool demonstrates how to:
1. Start the `TrustedInstaller` service programmatically.
2. Locate its running process.
3. Open and duplicate its token.
4. Impersonate the token to temporarily gain its privileges.
