//! The §6.3 key schedule, transcript hashes, signatures and the SAS.

use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::{HandshakeError, EPOCH_ID_SIZE, SAS_NONCE_SIZE};
use crate::suite::kid::Kid;
use crate::suite::{
    ct_eq, labeled_hash, sign, KEY_SIZE, KID_SIZE, LABEL_EPOCH, LABEL_I2R, LABEL_KID_I2R, LABEL_KID_R2I, LABEL_R2I, LABEL_RK,
    LABEL_SAS, LABEL_SAS_COMMIT, LABEL_SESSION, LABEL_SIG_FIN, LABEL_SIG_RESP, LABEL_TH, LABEL_TH1,
};

/// Every value of the key schedule for one handshake. Its secrets wipe
/// themselves; `Debug` prints nothing.
pub struct Schedule {
    pub th1: [u8; 32],
    pub th: [u8; 32],
    pub(crate) prk: Zeroizing<[u8; 32]>,
    pub(crate) k_i2r: Zeroizing<[u8; KEY_SIZE]>,
    pub(crate) k_r2i: Zeroizing<[u8; KEY_SIZE]>,
    pub kid_i2r: Kid,
    pub kid_r2i: Kid,
    pub(crate) rk: Zeroizing<[u8; KEY_SIZE]>,
    pub epoch_id: [u8; EPOCH_ID_SIZE],
}

impl std::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Schedule(..)")
    }
}

/// `th1 = SHA-256("vettid/vms/2/th1" || env_init)`.
pub fn th1(env_init: &[u8]) -> [u8; 32] {
    labeled_hash(LABEL_TH1, &[env_init])
}

/// `th = SHA-256("vettid/vms/2/th" || env_init || resp_header)`, where
/// `resp_header` is `hs.resp` bytes [0:1140].
pub fn th(env_init: &[u8], resp_header: &[u8]) -> [u8; 32] {
    labeled_hash(LABEL_TH, &[env_init, resp_header])
}

fn expand<const N: usize>(hk: &Hkdf<Sha256>, label: &str, parts: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let mut info = label.as_bytes().to_vec();
    for p in parts {
        info.extend_from_slice(p);
    }
    let mut out = Zeroizing::new([0u8; N]);
    hk.expand(&info, &mut out[..]).expect("N is far below 255 * 32");
    out
}

impl Schedule {
    /// Run §6.3 from `K_s`, `K_e` and the transcript hashes:
    /// `prk = HKDF-Extract(salt = "vettid/vms/2/session", K_e || K_s)`, then
    /// the directional keys, kids, `rk` and `epoch_id` over `th`.
    pub fn derive(ks: &[u8; KEY_SIZE], ke: &[u8; KEY_SIZE], th1: [u8; 32], th: [u8; 32]) -> Self {
        let mut ikm = Zeroizing::new([0u8; 2 * KEY_SIZE]);
        ikm[..KEY_SIZE].copy_from_slice(ke);
        ikm[KEY_SIZE..].copy_from_slice(ks);
        let (mut prk, hk) = Hkdf::<Sha256>::extract(Some(LABEL_SESSION.as_bytes()), &ikm[..]);
        let mut prk_bytes = Zeroizing::new([0u8; 32]);
        prk_bytes.copy_from_slice(&prk);
        prk.as_mut_slice().zeroize();
        // hkdf 0.12 doesn't wipe its HMAC state (`hk`) on drop; it lives
        // only for this function (as in Go, whose HKDF keeps such copies).
        let kid = |label| Kid(*expand::<KID_SIZE>(&hk, label, &[&th]));
        Schedule {
            th1,
            th,
            prk: prk_bytes,
            k_i2r: expand(&hk, LABEL_I2R, &[&th]),
            k_r2i: expand(&hk, LABEL_R2I, &[&th]),
            kid_i2r: kid(LABEL_KID_I2R),
            kid_r2i: kid(LABEL_KID_R2I),
            rk: expand(&hk, LABEL_RK, &[&th]),
            epoch_id: *expand::<EPOCH_ID_SIZE>(&hk, LABEL_EPOCH, &[&th]),
        }
    }
}

/// `sas_commit = SHA-256("vettid/vms/2/sas-commit" || n_I)`.
pub fn sas_commit(n_i: &[u8; SAS_NONCE_SIZE]) -> [u8; 32] {
    labeled_hash(LABEL_SAS_COMMIT, &[n_i])
}

/// Whether `n_i` opens `commit`, in constant time.
pub fn check_sas_commit(commit: &[u8], n_i: &[u8]) -> bool {
    let Ok(n) = <&[u8; SAS_NONCE_SIZE]>::try_from(n_i) else { return false };
    ct_eq(&sas_commit(n), commit)
}

/// The SAS (§6.3, 0.10.3): `uint32be(HKDF-Expand(prk, "vettid/vms/2/sas"
/// || th || n_I || n_R, 4)) mod 1,000,000`, as 6 zero-padded digits.
pub fn sas(s: &Schedule, n_i: &[u8], n_r: &[u8]) -> Result<String, HandshakeError> {
    if n_i.len() != SAS_NONCE_SIZE || n_r.len() != SAS_NONCE_SIZE {
        return Err(HandshakeError::Body);
    }
    let hk = Hkdf::<Sha256>::from_prk(&s.prk[..]).map_err(|_| HandshakeError::Body)?;
    let b = expand::<4>(&hk, LABEL_SAS, &[&s.th, n_i, n_r]);
    Ok(format!("{:06}", u32::from_be_bytes(*b) % 1_000_000))
}

/// `sig_R = Ed25519(ik_R, "vettid/vms/2/sig-resp" || th)`.
pub fn sign_resp(ik: &SigningKey, th: &[u8; 32]) -> [u8; 64] {
    sign::sign(ik, LABEL_SIG_RESP, th)
}

/// `sig_I = Ed25519(ik_I, "vettid/vms/2/sig-fin" || th)`.
pub fn sign_fin(ik: &SigningKey, th: &[u8; 32]) -> [u8; 64] {
    sign::sign(ik, LABEL_SIG_FIN, th)
}

/// Check `sig_R`.
pub fn verify_resp(ik: &VerifyingKey, th: &[u8; 32], sig: &[u8]) -> Result<(), HandshakeError> {
    sign::verify(ik, LABEL_SIG_RESP, th, sig).map_err(|_| HandshakeError::SigResp)
}

/// Check `sig_I`.
pub fn verify_fin(ik: &VerifyingKey, th: &[u8; 32], sig: &[u8]) -> Result<(), HandshakeError> {
    sign::verify(ik, LABEL_SIG_FIN, th, sig).map_err(|_| HandshakeError::Body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::vectors;

    /// handshake.json: the schedule from its K_s, K_e, th1 and th.
    #[test]
    fn schedule_vector() {
        let v = vectors::load("handshake");
        let k = |n: &str| -> [u8; 32] { vectors::hex(&v[n]).try_into().unwrap() };
        let s = Schedule::derive(&k("K_s_hex"), &k("K_e_hex"), k("th1_hex"), k("th_hex"));
        assert_eq!(*s.prk, k("prk_hex"));
        assert_eq!(*s.k_i2r, k("k_i2r_hex"));
        assert_eq!(*s.k_r2i, k("k_r2i_hex"));
        assert_eq!(s.kid_i2r.0.to_vec(), vectors::hex(&v["kid_i2r_hex"]));
        assert_eq!(s.kid_r2i.0.to_vec(), vectors::hex(&v["kid_r2i_hex"]));
        assert_eq!(*s.rk, k("rk_hex"));
        assert_eq!(s.epoch_id.to_vec(), vectors::hex(&v["epoch_id_hex"]));
        let n_i: [u8; 32] = vectors::hex(&v["inputs"]["n_I_hex"]).try_into().unwrap();
        let n_r = vectors::hex(&v["inputs"]["n_R_hex"]);
        assert_eq!(sas_commit(&n_i).to_vec(), vectors::hex(&v["sas_commit_hex"]));
        assert!(check_sas_commit(&sas_commit(&n_i), &n_i));
        assert!(!check_sas_commit(&sas_commit(&n_i), &n_r));
        assert!(!check_sas_commit(&sas_commit(&n_i), &n_i[..31]));
        assert_eq!(sas(&s, &n_i, &n_r).unwrap(), v["sas"].as_str().unwrap());
        assert_eq!(sas(&s, &n_i, &n_r[..31]), Err(HandshakeError::Body));
        assert_eq!(format!("{s:?}"), "Schedule(..)");
    }
}
