//! Wire framing, deterministic CBOR, and content addressing (Soal Protocol v0.2).
//!
//! **Universal rule (INV-CID-WIRE-01, INV-IROH-01):**
//! `cid(O) = BLAKE3(wire_bytes(O))` for every object transferred via iroh-blobs
//! or stored under a typed CID.
//!
//! Typed objects use a **16-byte domain prefix frame**:
//! `wire = DOMAIN || body`, `cid = BLAKE3(wire)`.
//! Chunks remain untyped: `wire = StoredBlob`, `cid = BLAKE3(wire)`.
//!
//! CBOR uses **preferred encoding** (RFC 8949 §4.2.1): definite lengths, shortest
//! integer forms, integer map keys sorted ascending, map tstr keys UTF-8 sorted.

use crate::commit::Commit;
use crate::tree::{Tree, TreeEntry};
use crate::{ContentHash, SoalError};

/// Exactly 16 bytes: ASCII domain tag, NUL-padded on the right.
pub type Domain = [u8; 16];

/// `soal/tree/v1` + 4 NUL
pub const DOMAIN_TREE: Domain = *b"soal/tree/v1\0\0\0\0";
/// `soal/commit/v1` + 2 NUL
pub const DOMAIN_COMMIT: Domain = *b"soal/commit/v1\0\0";
/// `soal/config/v1` + 2 NUL
pub const DOMAIN_CONFIG: Domain = *b"soal/config/v1\0\0";
/// `soal/head/v1` + 4 NUL
pub const DOMAIN_HEAD: Domain = *b"soal/head/v1\0\0\0\0";
/// `soal/invite/v1` + 2 NUL
pub const DOMAIN_INVITE: Domain = *b"soal/invite/v1\0\0";

pub const PROTOCOL_VERSION: u64 = 1;
pub const MAX_COMMIT_PARENTS: usize = 16;
pub const MAX_TREE_ENTRIES: usize = 1_000_000;

/// Frame body with a domain prefix: `DOMAIN || body`.
pub fn frame(domain: &Domain, body: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(16 + body.len());
    w.extend_from_slice(domain);
    w.extend_from_slice(body);
    w
}

/// Content ID of arbitrary wire bytes.
#[inline]
pub fn cid_of(wire: &[u8]) -> ContentHash {
    ContentHash::of(wire)
}

/// Strip and verify domain prefix; return body slice.
pub fn unframe<'a>(domain: &Domain, wire: &'a [u8]) -> Result<&'a [u8], SoalError> {
    if wire.len() < 16 {
        return Err(SoalError::Verify("wire too short for domain frame".into()));
    }
    if &wire[..16] != domain.as_slice() {
        return Err(SoalError::Verify("domain mismatch".into()));
    }
    Ok(&wire[16..])
}

/// Verify that `BLAKE3(wire) == expected` and domain matches; return body.
pub fn verify_framed(
    domain: &Domain,
    expected: ContentHash,
    wire: &[u8],
) -> Result<Vec<u8>, SoalError> {
    let actual = cid_of(wire);
    if actual != expected {
        return Err(SoalError::hash_mismatch(&expected, &actual));
    }
    let body = unframe(domain, wire)?;
    Ok(body.to_vec())
}

/// Build framed wire and return `(cid, wire)`.
pub fn frame_cid(domain: &Domain, body: &[u8]) -> (ContentHash, Vec<u8>) {
    let wire = frame(domain, body);
    let cid = cid_of(&wire);
    (cid, wire)
}

// ---------------------------------------------------------------------------
// Deterministic CBOR (preferred encoding)
// ---------------------------------------------------------------------------

fn push_uint(buf: &mut Vec<u8>, major: u8, v: u64) {
    if v < 24 {
        buf.push((major << 5) | (v as u8));
    } else if v <= u8::MAX as u64 {
        buf.push((major << 5) | 24);
        buf.push(v as u8);
    } else if v <= u16::MAX as u64 {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= u32::MAX as u64 {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    push_uint(buf, 0, v);
}

fn write_bstr(buf: &mut Vec<u8>, data: &[u8]) {
    push_uint(buf, 2, data.len() as u64);
    buf.extend_from_slice(data);
}

fn write_tstr(buf: &mut Vec<u8>, s: &str) {
    push_uint(buf, 3, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn write_array_header(buf: &mut Vec<u8>, len: usize) {
    push_uint(buf, 4, len as u64);
}

fn write_map_header(buf: &mut Vec<u8>, len: usize) {
    push_uint(buf, 5, len as u64);
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SoalError> {
        if self.pos + n > self.data.len() {
            return Err(SoalError::Verify("CBOR truncated".into()));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn take_u8(&mut self) -> Result<u8, SoalError> {
        Ok(self.take(1)?[0])
    }

    fn read_uint(&mut self) -> Result<(u8, u64), SoalError> {
        let b = self.take_u8()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        let v = match ai {
            n if n < 24 => n as u64,
            24 => self.take_u8()? as u64,
            25 => {
                let x = self.take(2)?;
                u16::from_be_bytes([x[0], x[1]]) as u64
            }
            26 => {
                let x = self.take(4)?;
                u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64
            }
            27 => {
                let x = self.take(8)?;
                u64::from_be_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]])
            }
            _ => {
                return Err(SoalError::Verify(
                    "indefinite/reserved CBOR not allowed".into(),
                ))
            }
        };
        Ok((major, v))
    }

    fn expect_major_uint(&mut self, want_major: u8) -> Result<u64, SoalError> {
        let (major, v) = self.read_uint()?;
        if major != want_major {
            return Err(SoalError::Verify(format!(
                "CBOR major type {major}, expected {want_major}"
            )));
        }
        Ok(v)
    }

    fn read_bstr(&mut self) -> Result<&'a [u8], SoalError> {
        let len = self.expect_major_uint(2)? as usize;
        self.take(len)
    }

    fn read_tstr(&mut self) -> Result<&'a str, SoalError> {
        let len = self.expect_major_uint(3)? as usize;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes).map_err(|_| SoalError::Verify("CBOR tstr not UTF-8".into()))
    }

    fn read_array_header(&mut self) -> Result<usize, SoalError> {
        Ok(self.expect_major_uint(4)? as usize)
    }

    fn read_map_header(&mut self) -> Result<usize, SoalError> {
        Ok(self.expect_major_uint(5)? as usize)
    }

    fn read_u64_value(&mut self) -> Result<u64, SoalError> {
        self.expect_major_uint(0)
    }

    fn finish(self) -> Result<(), SoalError> {
        if self.pos != self.data.len() {
            return Err(SoalError::Verify("trailing CBOR bytes".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Author identity bytes (wire field 3)
// ---------------------------------------------------------------------------

/// Map author string to 32-byte wire field.
/// - 64-char hex → raw NodeID / ContentHash bytes
/// - else → BLAKE3(b"soal-author:" || utf8) (stable local placeholder)
pub fn author_to_bytes(author: &str) -> [u8; 32] {
    if let Ok(h) = ContentHash::from_hex(author) {
        return h.0;
    }
    let mut pre = Vec::with_capacity(12 + author.len());
    pre.extend_from_slice(b"soal-author:");
    pre.extend_from_slice(author.as_bytes());
    *blake3::hash(&pre).as_bytes()
}

pub fn author_from_bytes(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Tree wire (DOMAIN_TREE || cbor TreeBody)
// ---------------------------------------------------------------------------

/// Encode TreeBody CBOR (no domain frame).
pub fn encode_tree_body(tree: &Tree) -> Result<Vec<u8>, SoalError> {
    if tree.entries.len() > MAX_TREE_ENTRIES {
        return Err(SoalError::Verify("tree exceeds MAX_TREE_ENTRIES".into()));
    }
    let mut buf = Vec::new();
    // TreeBody = { 1: { * tstr => TreeEntry } }
    write_map_header(&mut buf, 1);
    write_u64(&mut buf, 1);
    write_map_header(&mut buf, tree.entries.len());
    // BTreeMap already sorts by path UTF-8
    for (path, entry) in &tree.entries {
        write_tstr(&mut buf, path);
        match entry {
            TreeEntry::File { size, chunks } => {
                // { 1: 0, 2: size, 3: [ * bstr-32 ] }
                write_map_header(&mut buf, 3);
                write_u64(&mut buf, 1);
                write_u64(&mut buf, 0);
                write_u64(&mut buf, 2);
                write_u64(&mut buf, *size);
                write_u64(&mut buf, 3);
                write_array_header(&mut buf, chunks.len());
                for c in chunks {
                    write_bstr(&mut buf, c.as_bytes());
                }
            }
            TreeEntry::Dir { hash } => {
                // { 1: 1, 2: bstr-32 }
                write_map_header(&mut buf, 2);
                write_u64(&mut buf, 1);
                write_u64(&mut buf, 1);
                write_u64(&mut buf, 2);
                write_bstr(&mut buf, hash.as_bytes());
            }
        }
    }
    Ok(buf)
}

/// Decode TreeBody CBOR (no domain frame). Rejects unknown keys.
pub fn decode_tree_body(data: &[u8]) -> Result<Tree, SoalError> {
    let mut cur = Cursor::new(data);
    let n = cur.read_map_header()?;
    if n != 1 {
        return Err(SoalError::Verify("TreeBody must have exactly key 1".into()));
    }
    let key = cur.read_u64_value()?;
    if key != 1 {
        return Err(SoalError::Verify(format!("unexpected TreeBody key {key}")));
    }
    let n_entries = cur.read_map_header()?;
    if n_entries > MAX_TREE_ENTRIES {
        return Err(SoalError::Verify("tree exceeds MAX_TREE_ENTRIES".into()));
    }
    let mut tree = Tree::new();
    let mut last_path: Option<String> = None;
    for _ in 0..n_entries {
        let path = cur.read_tstr()?.to_string();
        if let Some(ref prev) = last_path {
            if path.as_str() <= prev.as_str() {
                return Err(SoalError::Verify(
                    "tree entry keys not strictly sorted".into(),
                ));
            }
        }
        last_path = Some(path.clone());
        crate::tree::validate_path(&path)?;

        let em = cur.read_map_header()?;
        let mut entry_type: Option<u64> = None;
        let mut size: Option<u64> = None;
        let mut chunks: Option<Vec<ContentHash>> = None;
        let mut dir_hash: Option<ContentHash> = None;
        let mut last_k: Option<u64> = None;
        for _ in 0..em {
            let k = cur.read_u64_value()?;
            if let Some(prev) = last_k {
                if k <= prev {
                    return Err(SoalError::Verify("entry map keys not sorted".into()));
                }
            }
            last_k = Some(k);
            match k {
                1 => {
                    entry_type = Some(cur.read_u64_value()?);
                }
                2 => {
                    // size (file) or dir hash (dir) — decided by type
                    // Peek is hard; read as either: if next major is 2 (bstr) it's dir
                    // We already know from type if set
                    if entry_type == Some(1) {
                        let b = cur.read_bstr()?;
                        if b.len() != 32 {
                            return Err(SoalError::Verify("Dir hash must be 32 bytes".into()));
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(b);
                        dir_hash = Some(ContentHash::from_bytes(a));
                    } else {
                        size = Some(cur.read_u64_value()?);
                    }
                }
                3 => {
                    let alen = cur.read_array_header()?;
                    let mut ch = Vec::with_capacity(alen);
                    for _ in 0..alen {
                        let b = cur.read_bstr()?;
                        if b.len() != 32 {
                            return Err(SoalError::Verify("chunk CID must be 32 bytes".into()));
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(b);
                        ch.push(ContentHash::from_bytes(a));
                    }
                    chunks = Some(ch);
                }
                other => {
                    return Err(SoalError::Verify(format!("unknown TreeEntry key {other}")));
                }
            }
        }
        match entry_type {
            Some(0) => {
                let size = size.ok_or_else(|| SoalError::Verify("File missing size".into()))?;
                let chunks =
                    chunks.ok_or_else(|| SoalError::Verify("File missing chunks".into()))?;
                tree.entries.insert(path, TreeEntry::File { size, chunks });
            }
            Some(1) => {
                let hash = dir_hash.ok_or_else(|| SoalError::Verify("Dir missing hash".into()))?;
                tree.entries.insert(path, TreeEntry::Dir { hash });
            }
            _ => return Err(SoalError::Verify("TreeEntry missing/invalid type".into())),
        }
    }
    cur.finish()?;
    Ok(tree)
}

/// Full tree wire: DOMAIN_TREE || cbor(TreeBody).
pub fn encode_tree_wire(tree: &Tree) -> Result<Vec<u8>, SoalError> {
    let body = encode_tree_body(tree)?;
    Ok(frame(&DOMAIN_TREE, &body))
}

pub fn decode_tree_wire(wire: &[u8]) -> Result<Tree, SoalError> {
    let body = unframe(&DOMAIN_TREE, wire)?;
    decode_tree_body(body)
}

pub fn tree_cid(tree: &Tree) -> Result<ContentHash, SoalError> {
    Ok(cid_of(&encode_tree_wire(tree)?))
}

// ---------------------------------------------------------------------------
// Commit wire (DOMAIN_COMMIT || cbor CommitBody)
// ---------------------------------------------------------------------------

/// Encode CommitBody (includes protocol_version + signature; unsigned = 64 zero bytes).
pub fn encode_commit_body(commit: &Commit) -> Result<Vec<u8>, SoalError> {
    if commit.parents.len() > MAX_COMMIT_PARENTS {
        return Err(SoalError::Verify("too many parents".into()));
    }
    let author = author_to_bytes(&commit.author);
    let sig = commit.signature_bytes();
    let ver = if commit.protocol_version == 0 {
        PROTOCOL_VERSION
    } else {
        commit.protocol_version as u64
    };

    let mut buf = Vec::new();
    // CommitBody keys 1..7
    write_map_header(&mut buf, 7);
    write_u64(&mut buf, 1);
    write_bstr(&mut buf, commit.tree.as_bytes());
    write_u64(&mut buf, 2);
    write_array_header(&mut buf, commit.parents.len());
    for p in &commit.parents {
        write_bstr(&mut buf, p.as_bytes());
    }
    write_u64(&mut buf, 3);
    write_bstr(&mut buf, &author);
    write_u64(&mut buf, 4);
    write_u64(&mut buf, commit.timestamp);
    write_u64(&mut buf, 5);
    write_tstr(&mut buf, &commit.message);
    write_u64(&mut buf, 6);
    write_u64(&mut buf, ver);
    write_u64(&mut buf, 7);
    write_bstr(&mut buf, &sig);
    Ok(buf)
}

/// Sign preimage body: fields 1–6 only (no signature field).
pub fn encode_commit_sign_body(commit: &Commit) -> Result<Vec<u8>, SoalError> {
    if commit.parents.len() > MAX_COMMIT_PARENTS {
        return Err(SoalError::Verify("too many parents".into()));
    }
    let author = author_to_bytes(&commit.author);
    let ver = if commit.protocol_version == 0 {
        PROTOCOL_VERSION
    } else {
        commit.protocol_version as u64
    };
    let mut buf = Vec::new();
    write_map_header(&mut buf, 6);
    write_u64(&mut buf, 1);
    write_bstr(&mut buf, commit.tree.as_bytes());
    write_u64(&mut buf, 2);
    write_array_header(&mut buf, commit.parents.len());
    for p in &commit.parents {
        write_bstr(&mut buf, p.as_bytes());
    }
    write_u64(&mut buf, 3);
    write_bstr(&mut buf, &author);
    write_u64(&mut buf, 4);
    write_u64(&mut buf, commit.timestamp);
    write_u64(&mut buf, 5);
    write_tstr(&mut buf, &commit.message);
    write_u64(&mut buf, 6);
    write_u64(&mut buf, ver);
    Ok(buf)
}

/// Message bytes for ed25519: DOMAIN_COMMIT || cbor(SignBody).
pub fn commit_sign_message(commit: &Commit) -> Result<Vec<u8>, SoalError> {
    let body = encode_commit_sign_body(commit)?;
    Ok(frame(&DOMAIN_COMMIT, &body))
}

pub fn decode_commit_body(data: &[u8]) -> Result<Commit, SoalError> {
    let mut cur = Cursor::new(data);
    let n = cur.read_map_header()?;
    if n != 7 {
        return Err(SoalError::Verify(format!(
            "CommitBody must have 7 keys, got {n}"
        )));
    }
    let mut tree: Option<ContentHash> = None;
    let mut parents: Option<Vec<ContentHash>> = None;
    let mut author: Option<String> = None;
    let mut timestamp: Option<u64> = None;
    let mut message: Option<String> = None;
    let mut protocol_version: Option<u16> = None;
    let mut signature: Option<[u8; 64]> = None;
    let mut last_k: Option<u64> = None;

    for _ in 0..n {
        let k = cur.read_u64_value()?;
        if let Some(prev) = last_k {
            if k <= prev {
                return Err(SoalError::Verify("CommitBody keys not sorted".into()));
            }
        }
        last_k = Some(k);
        match k {
            1 => {
                let b = cur.read_bstr()?;
                if b.len() != 32 {
                    return Err(SoalError::Verify("tree CID len".into()));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                tree = Some(ContentHash::from_bytes(a));
            }
            2 => {
                let alen = cur.read_array_header()?;
                if alen > MAX_COMMIT_PARENTS {
                    return Err(SoalError::Verify("too many parents".into()));
                }
                let mut ps = Vec::with_capacity(alen);
                for _ in 0..alen {
                    let b = cur.read_bstr()?;
                    if b.len() != 32 {
                        return Err(SoalError::Verify("parent CID len".into()));
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(b);
                    ps.push(ContentHash::from_bytes(a));
                }
                parents = Some(ps);
            }
            3 => {
                let b = cur.read_bstr()?;
                if b.len() != 32 {
                    return Err(SoalError::Verify("author len".into()));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                author = Some(author_from_bytes(&a));
            }
            4 => timestamp = Some(cur.read_u64_value()?),
            5 => message = Some(cur.read_tstr()?.to_string()),
            6 => {
                let v = cur.read_u64_value()?;
                if v > u16::MAX as u64 {
                    return Err(SoalError::Verify("protocol_version overflow".into()));
                }
                protocol_version = Some(v as u16);
            }
            7 => {
                let b = cur.read_bstr()?;
                if b.len() != 64 {
                    return Err(SoalError::Verify("signature must be 64 bytes".into()));
                }
                let mut s = [0u8; 64];
                s.copy_from_slice(b);
                signature = Some(s);
            }
            other => {
                return Err(SoalError::Verify(format!("unknown CommitBody key {other}")));
            }
        }
    }
    cur.finish()?;

    Ok(Commit {
        tree: tree.ok_or_else(|| SoalError::Verify("missing tree".into()))?,
        parents: parents.ok_or_else(|| SoalError::Verify("missing parents".into()))?,
        author: author.ok_or_else(|| SoalError::Verify("missing author".into()))?,
        timestamp: timestamp.ok_or_else(|| SoalError::Verify("missing timestamp".into()))?,
        message: message.ok_or_else(|| SoalError::Verify("missing message".into()))?,
        protocol_version: protocol_version.unwrap_or(1),
        signature: signature.map(hex::encode),
    })
}

pub fn encode_commit_wire(commit: &Commit) -> Result<Vec<u8>, SoalError> {
    let body = encode_commit_body(commit)?;
    Ok(frame(&DOMAIN_COMMIT, &body))
}

pub fn decode_commit_wire(wire: &[u8]) -> Result<Commit, SoalError> {
    let body = unframe(&DOMAIN_COMMIT, wire)?;
    decode_commit_body(body)
}

pub fn commit_cid(commit: &Commit) -> Result<ContentHash, SoalError> {
    Ok(cid_of(&encode_commit_wire(commit)?))
}

// ---------------------------------------------------------------------------
// Protocol caps (DoS / safety) — design §B.9
// ---------------------------------------------------------------------------

/// Max simultaneous non-ancestor heads tracked locally.
pub const MAX_HEADS: usize = 64;
/// Max bytes for a single gossip message.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Max single blob size (chunk max ~8 MiB + AEAD overhead).
pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
/// Max commits walked in one sync DAG job.
pub const MAX_JOB_COMMITS: usize = 10_000;
/// Head announcement timestamp skew allowance (seconds).
pub const MAX_SKEW_SECS: u64 = 300;
/// Vault ID length in bytes.
pub const VAULT_ID_LEN: usize = 16;

// ---------------------------------------------------------------------------
// HeadAnnouncement wire (gossip CBOR body; sign preimage uses DOMAIN_HEAD)
// ---------------------------------------------------------------------------

/// Signed head announcement (design §B.8).
///
/// Gossip payload = raw CBOR `HeadAnnBody` (not domain-framed).
/// Sign message = `DOMAIN_HEAD || cbor(SignAnn)` where SignAnn excludes
/// vault_name (field 3) and signature (field 9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadAnnouncement {
    pub protocol_version: u64,
    /// Exactly 16 bytes.
    pub vault_id: [u8; VAULT_ID_LEN],
    /// Display hint only — NOT covered by signature.
    pub vault_name: String,
    pub head: ContentHash,
    pub timestamp: u64,
    /// 32-byte NodeID / public key.
    pub node_id: [u8; 32],
    /// Per-node monotonic sequence (INV-REPLAY-01).
    pub seq: u64,
    /// Membership generation binding.
    pub config_seq: u64,
    /// 64-byte ed25519 signature (zeros = unsigned / invalid for production).
    pub signature: [u8; 64],
}

impl HeadAnnouncement {
    pub fn vault_id_hex(&self) -> String {
        hex::encode(self.vault_id)
    }

    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }

    pub fn head_hex(&self) -> String {
        self.head.to_hex()
    }

    pub fn is_signed(&self) -> bool {
        self.signature != [0u8; 64]
    }
}

/// Topic id bytes for a vault: `BLAKE3(b"soal/v1/vault/" || vault_id)`.
pub fn vault_topic_hash(vault_id: &[u8; VAULT_ID_LEN]) -> ContentHash {
    let mut pre = Vec::with_capacity(14 + VAULT_ID_LEN);
    pre.extend_from_slice(b"soal/v1/vault/");
    pre.extend_from_slice(vault_id);
    ContentHash::of(&pre)
}

/// Encode SignAnn CBOR (fields 1,2,4,5,6,7,8 — no name, no sig).
pub fn encode_head_sign_body(ann: &HeadAnnouncement) -> Result<Vec<u8>, SoalError> {
    let mut buf = Vec::new();
    write_map_header(&mut buf, 6);
    write_u64(&mut buf, 1);
    write_u64(&mut buf, ann.protocol_version);
    write_u64(&mut buf, 2);
    write_bstr(&mut buf, &ann.vault_id);
    write_u64(&mut buf, 4);
    write_bstr(&mut buf, ann.head.as_bytes());
    write_u64(&mut buf, 5);
    write_u64(&mut buf, ann.timestamp);
    write_u64(&mut buf, 6);
    write_bstr(&mut buf, &ann.node_id);
    write_u64(&mut buf, 7);
    write_u64(&mut buf, ann.seq);
    write_u64(&mut buf, 8);
    write_u64(&mut buf, ann.config_seq);
    Ok(buf)
}

/// Sign preimage: DOMAIN_HEAD || cbor(SignAnn).
pub fn head_sign_message(ann: &HeadAnnouncement) -> Result<Vec<u8>, SoalError> {
    let body = encode_head_sign_body(ann)?;
    Ok(frame(&DOMAIN_HEAD, &body))
}

/// Encode full HeadAnnBody CBOR for gossip (9 keys).
pub fn encode_head_announcement(ann: &HeadAnnouncement) -> Result<Vec<u8>, SoalError> {
    if ann.vault_name.len() > 1024 {
        return Err(SoalError::Verify("vault_name too long".into()));
    }
    let mut buf = Vec::new();
    write_map_header(&mut buf, 9);
    write_u64(&mut buf, 1);
    write_u64(&mut buf, ann.protocol_version);
    write_u64(&mut buf, 2);
    write_bstr(&mut buf, &ann.vault_id);
    write_u64(&mut buf, 3);
    write_tstr(&mut buf, &ann.vault_name);
    write_u64(&mut buf, 4);
    write_bstr(&mut buf, ann.head.as_bytes());
    write_u64(&mut buf, 5);
    write_u64(&mut buf, ann.timestamp);
    write_u64(&mut buf, 6);
    write_bstr(&mut buf, &ann.node_id);
    write_u64(&mut buf, 7);
    write_u64(&mut buf, ann.seq);
    write_u64(&mut buf, 8);
    write_u64(&mut buf, ann.config_seq);
    write_u64(&mut buf, 9);
    write_bstr(&mut buf, &ann.signature);
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(SoalError::Verify(
            "head announcement exceeds MAX_MESSAGE_BYTES".into(),
        ));
    }
    Ok(buf)
}

/// Decode HeadAnnBody CBOR. Rejects unknown keys.
pub fn decode_head_announcement(data: &[u8]) -> Result<HeadAnnouncement, SoalError> {
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(SoalError::Verify("head announcement too large".into()));
    }
    let mut cur = Cursor::new(data);
    let n = cur.read_map_header()?;
    if n != 9 {
        return Err(SoalError::Verify(format!(
            "HeadAnnBody must have 9 keys, got {n}"
        )));
    }
    let mut protocol_version: Option<u64> = None;
    let mut vault_id: Option<[u8; VAULT_ID_LEN]> = None;
    let mut vault_name: Option<String> = None;
    let mut head: Option<ContentHash> = None;
    let mut timestamp: Option<u64> = None;
    let mut node_id: Option<[u8; 32]> = None;
    let mut seq: Option<u64> = None;
    let mut config_seq: Option<u64> = None;
    let mut signature: Option<[u8; 64]> = None;
    let mut last_k: Option<u64> = None;

    for _ in 0..n {
        let k = cur.read_u64_value()?;
        if let Some(prev) = last_k {
            if k <= prev {
                return Err(SoalError::Verify("HeadAnnBody keys not sorted".into()));
            }
        }
        last_k = Some(k);
        match k {
            1 => protocol_version = Some(cur.read_u64_value()?),
            2 => {
                let b = cur.read_bstr()?;
                if b.len() != VAULT_ID_LEN {
                    return Err(SoalError::Verify("vault_id must be 16 bytes".into()));
                }
                let mut a = [0u8; VAULT_ID_LEN];
                a.copy_from_slice(b);
                vault_id = Some(a);
            }
            3 => vault_name = Some(cur.read_tstr()?.to_string()),
            4 => {
                let b = cur.read_bstr()?;
                if b.len() != 32 {
                    return Err(SoalError::Verify("head CID must be 32 bytes".into()));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                head = Some(ContentHash::from_bytes(a));
            }
            5 => timestamp = Some(cur.read_u64_value()?),
            6 => {
                let b = cur.read_bstr()?;
                if b.len() != 32 {
                    return Err(SoalError::Verify("node_id must be 32 bytes".into()));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                node_id = Some(a);
            }
            7 => seq = Some(cur.read_u64_value()?),
            8 => config_seq = Some(cur.read_u64_value()?),
            9 => {
                let b = cur.read_bstr()?;
                if b.len() != 64 {
                    return Err(SoalError::Verify("signature must be 64 bytes".into()));
                }
                let mut s = [0u8; 64];
                s.copy_from_slice(b);
                signature = Some(s);
            }
            other => {
                return Err(SoalError::Verify(format!(
                    "unknown HeadAnnBody key {other}"
                )));
            }
        }
    }
    cur.finish()?;

    Ok(HeadAnnouncement {
        protocol_version: protocol_version
            .ok_or_else(|| SoalError::Verify("missing protocol_version".into()))?,
        vault_id: vault_id.ok_or_else(|| SoalError::Verify("missing vault_id".into()))?,
        vault_name: vault_name.ok_or_else(|| SoalError::Verify("missing vault_name".into()))?,
        head: head.ok_or_else(|| SoalError::Verify("missing head".into()))?,
        timestamp: timestamp.ok_or_else(|| SoalError::Verify("missing timestamp".into()))?,
        node_id: node_id.ok_or_else(|| SoalError::Verify("missing node_id".into()))?,
        seq: seq.ok_or_else(|| SoalError::Verify("missing seq".into()))?,
        config_seq: config_seq.ok_or_else(|| SoalError::Verify("missing config_seq".into()))?,
        signature: signature.ok_or_else(|| SoalError::Verify("missing signature".into()))?,
    })
}

/// Parse vault_id from 32-char hex.
pub fn vault_id_from_hex(s: &str) -> Result<[u8; VAULT_ID_LEN], SoalError> {
    let s = s.trim();
    if s.len() != VAULT_ID_LEN * 2 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SoalError::Other("vault_id must be 32 hex chars".into()));
    }
    let bytes = hex::decode(s).map_err(|_| SoalError::Other("invalid vault_id hex".into()))?;
    let mut a = [0u8; VAULT_ID_LEN];
    a.copy_from_slice(&bytes);
    Ok(a)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Tree;

    #[test]
    fn domain_constants_are_16_bytes() {
        assert_eq!(DOMAIN_TREE.len(), 16);
        assert_eq!(DOMAIN_COMMIT.len(), 16);
        assert_eq!(&DOMAIN_TREE[..12], b"soal/tree/v1");
        assert_eq!(&DOMAIN_COMMIT[..14], b"soal/commit/v1");
    }

    #[test]
    fn frame_unframe_roundtrip() {
        let body = b"hello";
        let wire = frame(&DOMAIN_TREE, body);
        assert_eq!(unframe(&DOMAIN_TREE, &wire).unwrap(), body);
    }

    #[test]
    fn cid_equals_blake3_of_wire() {
        let (cid, wire) = frame_cid(&DOMAIN_TREE, b"body");
        assert_eq!(cid, ContentHash::of(&wire));
        assert_ne!(cid, ContentHash::of(b"body"));
    }

    #[test]
    fn unframe_rejects_wrong_domain() {
        let wire = frame(&DOMAIN_TREE, b"x");
        assert!(unframe(&DOMAIN_COMMIT, &wire).is_err());
    }

    #[test]
    fn empty_tree_wire_roundtrip_and_stable() {
        let tree = Tree::new();
        let wire = encode_tree_wire(&tree).unwrap();
        assert_eq!(&wire[..16], DOMAIN_TREE.as_slice());
        let back = decode_tree_wire(&wire).unwrap();
        assert!(back.entries.is_empty());
        let cid = cid_of(&wire);
        assert_eq!(tree_cid(&tree).unwrap(), cid);
        // Stable: encode twice
        assert_eq!(encode_tree_wire(&tree).unwrap(), wire);
    }

    #[test]
    fn tree_with_file_wire_roundtrip() {
        let mut tree = Tree::new();
        tree.add_file("a.txt", 5, vec![ContentHash::from([0x11; 32])]);
        let wire = encode_tree_wire(&tree).unwrap();
        let back = decode_tree_wire(&wire).unwrap();
        assert_eq!(tree, back);
        assert_eq!(tree_cid(&tree).unwrap(), cid_of(&wire));
    }

    #[test]
    fn tree_rejects_unknown_entry_key() {
        // Manually craft bad body: map with key 1 -> empty map is ok; inject bad entry
        let mut buf = Vec::new();
        write_map_header(&mut buf, 1);
        write_u64(&mut buf, 1);
        write_map_header(&mut buf, 1);
        write_tstr(&mut buf, "x");
        write_map_header(&mut buf, 1);
        write_u64(&mut buf, 99); // unknown
        write_u64(&mut buf, 0);
        assert!(decode_tree_body(&buf).is_err());
    }

    #[test]
    fn commit_wire_roundtrip() {
        let c = Commit {
            tree: ContentHash::from([7u8; 32]),
            parents: vec![],
            author: "soal-local".into(),
            timestamp: 1,
            message: "init".into(),
            protocol_version: 1,
            signature: None,
        };
        let wire = encode_commit_wire(&c).unwrap();
        assert_eq!(&wire[..16], DOMAIN_COMMIT.as_slice());
        let back = decode_commit_wire(&wire).unwrap();
        assert_eq!(back.tree, c.tree);
        assert_eq!(back.timestamp, 1);
        assert_eq!(back.message, "init");
        assert_eq!(back.protocol_version, 1);
        // author becomes hex of derived bytes
        assert_eq!(
            back.author,
            author_from_bytes(&author_to_bytes("soal-local"))
        );
        assert_eq!(commit_cid(&c).unwrap(), cid_of(&wire));
    }

    #[test]
    fn commit_sign_body_excludes_sig() {
        let c = Commit {
            tree: ContentHash::from([1u8; 32]),
            parents: vec![ContentHash::from([2u8; 32])],
            author: ContentHash::from([3u8; 32]).to_hex(),
            timestamp: 42,
            message: "m".into(),
            protocol_version: 1,
            signature: Some(hex::encode([9u8; 64])),
        };
        let sign = encode_commit_sign_body(&c).unwrap();
        let full = encode_commit_body(&c).unwrap();
        assert!(full.len() > sign.len());
        // sign message framed
        let msg = commit_sign_message(&c).unwrap();
        assert_eq!(&msg[..16], DOMAIN_COMMIT.as_slice());
    }

    #[test]
    fn author_hex_passthrough() {
        let id = ContentHash::from([0xABu8; 32]);
        let hex = id.to_hex();
        assert_eq!(author_to_bytes(&hex), id.0);
    }

    #[test]
    fn different_domains_different_cids() {
        let body = b"same";
        let (c1, _) = frame_cid(&DOMAIN_TREE, body);
        let (c2, _) = frame_cid(&DOMAIN_COMMIT, body);
        assert_ne!(c1, c2);
    }

    #[test]
    fn golden_empty_tree_cid_locked() {
        let tree = Tree::new();
        let wire = encode_tree_wire(&tree).unwrap();
        let cid = cid_of(&wire).to_hex();
        // Re-encode must match — golden stability
        assert_eq!(cid_of(&encode_tree_wire(&tree).unwrap()).to_hex(), cid);
        assert_eq!(wire.len(), 16 + encode_tree_body(&tree).unwrap().len());
    }

    #[test]
    fn head_announcement_roundtrip() {
        let ann = HeadAnnouncement {
            protocol_version: 1,
            vault_id: [0xABu8; 16],
            vault_name: "photos".into(),
            head: ContentHash::from([0x11u8; 32]),
            timestamp: 1_700_000_000,
            node_id: [0x22u8; 32],
            seq: 7,
            config_seq: 1,
            signature: [0x33u8; 64],
        };
        let bytes = encode_head_announcement(&ann).unwrap();
        let back = decode_head_announcement(&bytes).unwrap();
        assert_eq!(back, ann);
        // Sign body excludes name + sig
        let sign = encode_head_sign_body(&ann).unwrap();
        assert!(sign.len() < bytes.len());
        let msg = head_sign_message(&ann).unwrap();
        assert_eq!(&msg[..16], DOMAIN_HEAD.as_slice());
    }

    #[test]
    fn vault_topic_is_stable() {
        let id = [9u8; 16];
        let t1 = vault_topic_hash(&id);
        let t2 = vault_topic_hash(&id);
        assert_eq!(t1, t2);
        assert_ne!(t1, vault_topic_hash(&[8u8; 16]));
    }

    #[test]
    fn head_rejects_wrong_key_count() {
        let mut buf = Vec::new();
        write_map_header(&mut buf, 1);
        write_u64(&mut buf, 1);
        write_u64(&mut buf, 1);
        assert!(decode_head_announcement(&buf).is_err());
    }

    #[test]
    fn head_encode_is_deterministic() {
        let ann = HeadAnnouncement {
            protocol_version: 1,
            vault_id: [0x01u8; 16],
            vault_name: "det".into(),
            head: ContentHash::from([0x02u8; 32]),
            timestamp: 99,
            node_id: [0x03u8; 32],
            seq: 4,
            config_seq: 1,
            signature: [0x04u8; 64],
        };
        let a = encode_head_announcement(&ann).unwrap();
        let b = encode_head_announcement(&ann).unwrap();
        assert_eq!(a, b);
    }
}
