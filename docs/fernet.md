# Fernet (mode 99998)

This custom hash mode cracks Fernet tokens where the key is derived as:

```
key = SHA256(passphrase)
```

Hash format:

```
gAAAAA... (Fernet token, base64url, padding optional)
```

Quick test:

```
./hashcat -m 99998 -a 0 example99998.hash example99998.dict
```

Notes:
- The module verifies the HMAC (SHA256) portion of the Fernet token.
- Fernet tokens must be contiguous base64url strings.
- On macOS, you may need an OpenCL CPU backend (e.g., POCL) to run on CPU.
- If you see "Metal is not supported", try `--backend-ignore-metal` and ensure an OpenCL backend is installed.
