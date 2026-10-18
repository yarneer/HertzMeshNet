//! Machine Key（ed25519，向 Coordination Server 签挑战）与 Node Key（x25519，WireGuard 数据面）。
//! 私钥文件是唯一事实源：.pub 文件缺失时从私钥推导补写；已有文件一律复用、绝不重写。

use std::path::Path;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use x25519_dalek::PublicKey as NodePublicKey;
use x25519_dalek::StaticSecret as NodeStaticSecret;

const MACHINE_KEY_FILE: &str = "machine-key";
const NODE_KEY_FILE: &str = "node-key";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PUBLIC_FILE_MODE: u32 = 0o644;

pub struct KeyStore {
    machine: SigningKey,
    node: NodeStaticSecret,
}

impl KeyStore {
    /// 已有密钥文件就复用，缺失才生成。写文件走临时文件 + rename，崩溃不会留下半截密钥。
    pub fn load_or_create(state_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;

        // ed25519-dalek 2.2 起 SigningKey 的字节形式是 32 字节种子，而不是 私钥+公钥 64 字节。
        let machine_bytes = load_or_generate::<32>(state_dir, MACHINE_KEY_FILE, || {
            SigningKey::generate(&mut rand_core::OsRng).to_bytes()
        })?;
        let node_bytes = load_or_generate::<32>(state_dir, NODE_KEY_FILE, || {
            *NodeStaticSecret::random_from_rng(rand_core::OsRng).as_bytes()
        })?;

        let machine = SigningKey::from_bytes(&machine_bytes);
        let node = NodeStaticSecret::from(node_bytes);

        ensure_public_file(
            state_dir,
            "machine-key.pub",
            &machine.verifying_key().to_bytes(),
        )?;
        ensure_public_file(
            state_dir,
            "node-key.pub",
            &NodePublicKey::from(&node).to_bytes(),
        )?;

        Ok(Self { machine, node })
    }

    pub fn machine(&self) -> &SigningKey {
        &self.machine
    }

    pub fn machine_public(&self) -> [u8; 32] {
        self.machine.verifying_key().to_bytes()
    }

    pub fn node(&self) -> &NodeStaticSecret {
        &self.node
    }

    pub fn node_public(&self) -> [u8; 32] {
        NodePublicKey::from(&self.node).to_bytes()
    }
}

fn load_or_generate<const N: usize>(
    state_dir: &Path,
    file: &str,
    generate: impl FnOnce() -> [u8; N],
) -> anyhow::Result<[u8; N]> {
    let path = state_dir.join(file);
    if let Some(bytes) = read_b64::<N>(&path)? {
        return Ok(bytes);
    }
    let bytes = generate();
    write_file_atomic(&path, &bytes, PRIVATE_FILE_MODE)?;
    tracing::info!(file, "generated new key material");
    Ok(bytes)
}

fn read_b64<const N: usize>(path: &Path) -> anyhow::Result<Option<[u8; N]>> {
    // 只有"文件不存在"才走生成路径；读得出但内容坏必须报错，
    // 静默重新生成等于轮换 Node 身份。
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read key file {}", path.display()));
        }
    };
    let decoded = B64
        .decode(text.trim())
        .with_context(|| format!("invalid base64 in key file {}", path.display()))?;
    let bytes: [u8; N] = decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "key file {} holds {} bytes, expected {N}",
            path.display(),
            bytes.len()
        )
    })?;
    Ok(Some(bytes))
}

fn ensure_public_file(state_dir: &Path, file: &str, bytes: &[u8; 32]) -> anyhow::Result<()> {
    let path = state_dir.join(file);
    if path.exists() {
        return Ok(());
    }
    write_file_atomic(&path, bytes, PUBLIC_FILE_MODE)
}

fn write_file_atomic(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        file.write_all(B64.encode(bytes).as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    set_exact_mode(&tmp, mode)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} into place", tmp.display()))
}

fn set_exact_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    if perms.mode() & 0o777 == mode {
        return Ok(());
    }
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("failed to chmod {}", path.display()))
}
