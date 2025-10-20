# Hijack — TryHackMe

TryHackMe writeup for the **Hijack** box.

## Short description
Session-hijack → admin RCE → reverse shell → NFS/FTP recon → user `rick` → `doas`/`sudo` env abuse with `LD_LIBRARY_PATH` to load a malicious `libcrypt.so.1` and get root.

## Files
- `WriteUp.md` — full step-by-step walkthrough with corrected exploit code & notes  
- `screenshots/` — evidence and outputs

## Disclaimer
For learning & lab use only. Don’t run these techniques against systems you don’t own or have permission to test.

---
