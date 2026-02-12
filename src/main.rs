// RevaultPass - private password manager (user:password). Optional encryption.
// Data in ~/.revaultpass/ ; only accessible with key when encryption is used.

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

const MAGIC_ENCRYPTED: &[u8; 4] = b"RVP1";
const MAGIC_PLAIN: &[u8; 4] = b"RVP0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;

fn data_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "revaultpass", "revaultpass")
        .map(|d| d.data_dir().to_path_buf())
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    name: String,
    user: String,
    password: String,
}

fn read_passphrase(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    rpassword::read_password()
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], argon2::Error> {
    let mut key = [0u8; 32];
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, 1, Some(32))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon.hash_password_into(passphrase.as_bytes(), salt, &mut key)?;
    Ok(key)
}

fn encrypt(plain: &[u8], passphrase: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    RngCore::fill_bytes(&mut OsRng, &mut salt);
    RngCore::fill_bytes(&mut OsRng, &mut nonce);

    let key = derive_key(passphrase, &salt).map_err(|e| format!("argon2: {:?}", e))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("{:?}", e))?;
    let ciphertext = cipher
        .encrypt((&nonce).into(), plain)
        .map_err(|e| format!("{:?}", e))?;

    let mut out = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC_ENCRYPTED);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if data.len() < 4 + SALT_LEN + NONCE_LEN + 16 {
        return Err("file too short".into());
    }
    if &data[0..4] != MAGIC_ENCRYPTED {
        return Err("not encrypted or wrong format".into());
    }
    let salt = &data[4..4 + SALT_LEN];
    let nonce = &data[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[4 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt).map_err(|e| format!("argon2: {:?}", e))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("{:?}", e))?;
    let plain = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| "wrong passphrase or corrupted data")?;
    Ok(plain)
}

fn store_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("store.dat"))
}

fn load_entries(path: &PathBuf, passphrase: Option<&str>) -> Result<Vec<Entry>, Box<dyn std::error::Error + Send + Sync>> {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if data.len() < 4 {
        return Ok(Vec::new());
    }
    if &data[0..4] == MAGIC_PLAIN {
        let s = String::from_utf8_lossy(&data[4..]);
        let entries: Vec<Entry> = serde_json::from_str(&s).unwrap_or_default();
        return Ok(entries);
    }
    if &data[0..4] == MAGIC_ENCRYPTED {
        let pass = passphrase.ok_or("encrypted store: passphrase required (use same key you set with init)")?;
        let plain = decrypt(&data, pass)?;
        let entries: Vec<Entry> = serde_json::from_slice(&plain)?;
        return Ok(entries);
    }
    Ok(Vec::new())
}

fn save_entries(path: &PathBuf, entries: &[Entry], passphrase: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let json = serde_json::to_vec(entries)?;
    let data = if let Some(pass) = passphrase {
        encrypt(&json, pass)?
    } else {
        let mut out = MAGIC_PLAIN.to_vec();
        out.extend_from_slice(&json);
        out
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, data)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = store_path().ok_or("could not determine data directory")?;

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "init" => {
            println!("RevaultPass init. Encryption is recommended.");
            let pass = read_passphrase("Set master key (or leave empty for no encryption): ")?;
            let entries: Vec<Entry> = Vec::new();
            save_entries(&path, &entries, if pass.is_empty() { None } else { Some(&pass) })?;
            if pass.is_empty() {
                println!("Store created (unencrypted). Use 'revaultpass init' again to set a key.");
            } else {
                println!("Store created. Your data is encrypted with your key.");
            }
        }
        "add" => {
            let name = args.get(2).cloned().unwrap_or_else(|| "".into());
            let user = args.get(3).cloned().unwrap_or_else(|| "".into());
            let pass_entry = args.get(4).cloned();
            if name.is_empty() {
                println!("usage: revaultpass add <name> <user> [password]");
                return Ok(());
            }
            let password = pass_entry.unwrap_or_else(|| read_passphrase("Password: ").unwrap_or_default());
            let passphrase = read_passphrase("Master key (or Enter for no encryption): ")?;
            let use_key = !passphrase.is_empty();
            let mut entries = load_entries(&path, if use_key { Some(&passphrase) } else { None })?;
            if entries.iter().any(|e| e.name == name) {
                println!("Name already exists. Use a different name or delete first.");
                return Ok(());
            }
            entries.push(Entry { name, user, password });
            save_entries(&path, &entries, if use_key { Some(&passphrase) } else { None })?;
            println!("Saved.");
        }
        "list" => {
            let passphrase = read_passphrase("Master key (or press Enter if store is unencrypted): ")?;
            let entries = load_entries(&path, if passphrase.is_empty() { None } else { Some(&passphrase) })?;
            if entries.is_empty() {
                println!("(none)");
            } else {
                for e in &entries {
                    println!("  {}  ->  {}:****", e.name, e.user);
                }
            }
        }
        "get" => {
            let name = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if name.is_empty() {
                println!("usage: revaultpass get <name>");
                return Ok(());
            }
            let passphrase = read_passphrase("Master key (or Enter if unencrypted): ")?;
            let entries = load_entries(&path, if passphrase.is_empty() { None } else { Some(&passphrase) })?;
            if let Some(e) = entries.iter().find(|e| e.name == name) {
                println!("{}:{}", e.user, e.password);
            } else {
                println!("Not found.");
            }
        }
        "delete" => {
            let name = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if name.is_empty() {
                println!("usage: revaultpass delete <name>");
                return Ok(());
            }
            let passphrase = read_passphrase("Master key (or Enter if unencrypted): ")?;
            let key_opt = if passphrase.is_empty() { None } else { Some(passphrase.as_str()) };
            let mut entries = load_entries(&path, key_opt)?;
            let len_before = entries.len();
            entries.retain(|e| e.name != name);
            if entries.len() == len_before {
                println!("Not found.");
                return Ok(());
            }
            save_entries(&path, &entries, key_opt)?;
            println!("Deleted.");
        }
        "help" | _ => {
            println!("RevaultPass - password manager (user:password)");
            println!("  init              create store, set master key (recommended)");
            println!("  add <name> <user> [password]   add entry");
            println!("  list              list names (user:****)");
            println!("  get <name>        print user:password");
            println!("  delete <name>     remove entry");
        }
    }
    Ok(())
}
