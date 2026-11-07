# Paper5 encrypted workbench

Static, password-encrypted archive and dashboard hosted on GitHub Pages.

Open https://returndmutc-ui.github.io/paper5-workbench/ and enter the separately supplied password. All research pages and datasets, including their route catalog, are AES-256-GCM encrypted. PBKDF2-SHA-256 derives the key in your browser. Only ciphertext is stored in this repository.

The original cloud server is not required to browse this archive. The original server and training files remain intact. Model training still runs on the research computers; GitHub Pages serves the latest synchronized dashboard snapshot.

Passwords, GitHub credentials, SSH keys, source archives, plaintext research content and model checkpoints must never be committed here.
