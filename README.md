# RevaultPass

Private password manager. Stores entries as **user:password** per name. Lightweight, local-only, no cloud.

**Encryption (optional but recommended):** Set a master key with `init`. Without the key, data cannot be read. Uses Argon2id (key derivation) + ChaCha20-Poly1305 (encryption).

## Build

```bash
cd RevaultPass
cargo build --release
```

Requires Rust (e.g. `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`).

## Run

```bash
./target/release/revaultpass help
```

Or add to PATH. Data is stored in `~/.local/share/revaultpass/revaultpass/store.dat` (Linux).

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create store and set master key (recommended). Leave empty for no encryption. |
| `add <name> <user> [password]` | Add entry. Password prompted if omitted. |
| `list` | List all names (user:****). |
| `get <name>` | Print `user:password` for that name. |
| `delete <name>` | Remove entry. |
| `help` | Show commands. |

## Security

- Master key is never stored; only a salt and ciphertext are on disk.
- Use a strong passphrase. Without it, encrypted data is unreadable.
- Data stays on your machine; nothing is sent over the network.
