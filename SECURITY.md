# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting:
open the **Security** tab of this repository and choose **Report a vulnerability**.
Include the steps to reproduce it and what you expected to happen.

## What the server can and cannot see

The server stores, for each drop: the encrypted blob, a burn flag, a passphrase flag, a salt and a
hash of the passphrase verifier, a hash of the creator's burn token, and an expiry time.

The server never receives the decryption key (it stays in the link's `#fragment`), the passphrase,
the plaintext, or a file's name and type. It does not log requests, IP addresses or URLs.

## What this design does not protect against

- A person who gets the full link. Whoever has it can read the secret.
- A compromised browser, device or browser extension on the sender's or recipient's side.
- A malicious server operator who serves modified JavaScript. The code that encrypts is delivered
  by the server, so you should trust the host, or run your own copy.
- Weak passphrases. They are stretched with PBKDF2 but can still be guessed offline by someone who
  has the stored data.
- Metadata such as the size of a drop and when it was created.
