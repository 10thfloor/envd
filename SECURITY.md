# Security Policy

## Reporting a vulnerability

Please report security issues privately — **do not** open a public issue.

- GitHub: open a [private security advisory](https://github.com/10thfloor/envd/security/advisories/new)
- Email: remember.mackenzie@gmail.com

You'll get an acknowledgement as soon as possible. Please include steps to
reproduce and the impact you observed.

## Threat model — what envd does and does not protect

envd is honest about its boundaries. Read this before trusting it with anything.

**What it protects:**

- **Secrets at rest.** Each project's vault (`.envd/vault.json`) is encrypted with
  AES-256-GCM and is safe to commit. The encryption key is never stored in the repo
  — it lives in the macOS Keychain, or is derived from `ENVD_PASSPHRASE` via PBKDF2.
- **Plaintext sprawl.** Values are decrypted only in the daemon's memory and injected
  into the target process's environment. envd never writes plaintext `.env` files.
- **Wrong key.** Decryption is authenticated (GCM); a wrong key fails closed — the
  project shows as locked and nothing is injected.
- **Local IPC.** The daemon socket (`~/.envd/daemon.sock`) is created with `0600`
  permissions (owner-only).

**What it does NOT protect against:**

- **An attacker who already has code execution as your user.** By design, env
  injection is promptless — which means the Keychain key (or `ENVD_PASSPHRASE`) is
  reachable by processes running as you. Such a process can decrypt the vault. envd
  is not a defense against malware already running under your account.
- **A committed vault + a leaked key.** Anyone with both the repository and the
  decryption key can read every secret. Treat the key like a key.
- **Reference back-ends.** `op://` references are resolved by the 1Password CLI;
  their security is 1Password's. envd only shells out to `op read`.

If your threat model requires defending decrypted values from your own logged-in
account, you want a passphrase you type per session (and no key stored at rest) —
which trades away envd's "never think about it" auto-injection. That trade-off is
intentionally not the default.
