//! Linux: the TPM 2.0 as a protector, through the kernel's resource
//! manager at `/dev/tpmrm0` (DESKTOP-REWORK-PLAN §4 "At-rest protectors").
//! Bound to this computer: the data key is sealed in a TPM object that
//! can't leave this TPM (`fixedTPM`, `fixedParent`).
//!
//! - **The parent:** the persistent storage root key at `0x81000001` if it
//!   is there and is a storage key, else a primary key made with
//!   `CreatePrimary` in the owner (storage) hierarchy from the TCG
//!   Provisioning Guidance's SRK template for ECC NIST P-256: `fixedTPM`,
//!   `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`, `noDA`,
//!   `restricted`, `decrypt`; name algorithm SHA-256; AES-128-CFB; no scheme,
//!   no KDF; an empty auth policy and empty unique fields. The same template
//!   gives the same key from the same TPM, so nothing is made persistent. A
//!   transient primary is flushed when the operation ends.
//! - **The sealed object:** a keyed-hash object holding the 32-byte data
//!   key, `fixedTPM`, `fixedParent`, `userWithAuth`, `noDA`, with **no PCR
//!   policy** (so firmware and kernel updates don't lock the person out)
//!   and **no authValue**. Its commands use an HMAC session salted to the
//!   parent, so the data key crosses to and from the TPM encrypted.
//! - **The header's `wrapped_key`:** `[1, parent, len(public) as u16 BE,
//!   public (TPMT_PUBLIC), len(private) as u16 BE, private (TPM2B_PRIVATE's
//!   bytes)]`, where `parent` is 1 for the persistent SRK and 2 for the
//!   template primary, so a load uses the parent the seal used.
//! - Nothing is kept outside the file: [`Protector::remove_external`] is Ok.
//!
//! **Absent** only when opening `/dev/tpmrm0` gives `ENOENT` (no TPM, or a
//! Flatpak sandbox) or `EACCES` (many distributions give it to
//! `root:tss` only). Every other result is a TPM that is there, and any
//! error from it is **failing**: the storage hierarchy having an auth value,
//! the TPM busy or in lockout, an unseal error. A wrapped key that doesn't
//! parse, or that this TPM refuses as not its own (an integrity or value
//! error at load: a copy from another computer, a cleared TPM, a garbled
//! blob), **won't open**.
//!
//! Who can still open it: root, and any user who can read the file and use
//! the TPM, including any process of this user. Clearing the TPM loses the
//! pairing. Test TCTIs (`swtpm`) are `#[cfg(test)]` only.

use std::io;

use tss_esapi::attributes::{ObjectAttributes, ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::{CapabilityType, SessionType, Tss2ResponseCode, Tss2ResponseCodeKind};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    CapabilityData, Digest, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, Error as TssError, TctiNameConf};
use zeroize::Zeroizing;

use super::protector::{Availability, DataKey, Protector, ProtectorError, TPM_NAME as NAME};

/// The kernel's TPM resource manager.
const DEVICE: &str = "/dev/tpmrm0";
/// The conventional persistent handle of the storage root key.
const SRK_HANDLE: u32 = 0x8100_0001;
/// The first byte of the wrapped key.
const WRAPPED_VERSION: u8 = 1;
/// The parent byte: the persistent SRK, or a primary from the template.
const PARENT_PERSISTENT: u8 = 1;
const PARENT_TEMPLATE: u8 = 2;

/// Where the TPM is reached.
#[derive(Debug, Clone)]
enum Tcti {
    Device,
    /// A software TPM (`swtpm`) on localhost; tests only.
    #[cfg(test)]
    Swtpm(u16),
}

pub(super) struct Tpm {
    tcti: Tcti,
}

/// Availability from the result of opening the device (a seam for tests).
fn device_availability(opened: io::Result<()>) -> Availability {
    match opened {
        Ok(()) => Availability::Present,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Availability::Absent("no /dev/tpmrm0"),
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => Availability::Absent("/dev/tpmrm0 isn't usable by this user"),
        Err(e) => {
            // There, but not usable for another reason: the protector's own
            // calls fail with it (failing, never a quiet fallback).
            log::warn!("protector tpm: opening {DEVICE}: {:?}", e.kind());
            Availability::Present
        }
    }
}

fn failing(what: &str, e: TssError) -> ProtectorError {
    ProtectorError::Failing { by: NAME, detail: format!("{what}: {e}") }
}

fn rc_kind(e: &TssError) -> Option<(bool, Tss2ResponseCodeKind)> {
    match e {
        TssError::Tss2Error(rc @ Tss2ResponseCode::FormatOne(_)) => rc.kind().map(|k| (true, k)),
        TssError::Tss2Error(rc) => rc.kind().map(|k| (false, k)),
        TssError::WrapperError(_) => None,
    }
}

/// Whether a load's error says the blob isn't this TPM's or isn't well
/// formed (won't open), rather than that the TPM couldn't do it now
/// (failing). Only parameter errors of the TPM itself (format one) count.
fn is_bad_blob(e: &TssError) -> bool {
    use Tss2ResponseCodeKind as K;
    matches!(
        rc_kind(e),
        Some((
            true,
            K::Integrity
                | K::Size
                | K::Value
                | K::Key
                | K::Type
                | K::Attributes
                | K::Hash
                | K::Insufficient
                | K::Binding
                | K::Symmetric
                | K::Scheme
                | K::Kdf
                | K::Asymmetric
                | K::KeySize
                | K::ReservedBits
        ))
    )
}

/// Whether reading a persistent handle's public area says there is no
/// object there.
fn is_no_object(e: &TssError) -> bool {
    matches!(rc_kind(e), Some((true, Tss2ResponseCodeKind::Handle)))
}

/// The TCG SRK template, ECC NIST P-256 (module doc).
fn srk_template() -> Result<Public, TssError> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(SymmetricDefinitionObject::AES_128_CFB, EccCurve::NistP256).build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// The sealed object's attributes: in this TPM only, no auth, no DA.
fn sealed_attributes() -> Result<ObjectAttributes, TssError> {
    ObjectAttributesBuilder::new().with_fixed_tpm(true).with_fixed_parent(true).with_user_with_auth(true).with_no_da(true).build()
}

fn sealed_template() -> Result<Public, TssError> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(sealed_attributes()?)
        .with_auth_policy(Digest::default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
}

/// Whether `public` is a storage key: restricted, decrypt, not signing,
/// in this TPM only.
fn is_storage_key(public: &Public) -> bool {
    let a = public.object_attributes();
    a.restricted() && a.decrypt() && !a.sign_encrypt() && a.fixed_tpm() && a.fixed_parent()
}

/// Whether `public` is a sealed object as this protector makes them.
fn is_our_sealed_object(public: &Public) -> bool {
    match (public, sealed_attributes()) {
        (Public::KeyedHash { object_attributes, name_hashing_algorithm, auth_policy, parameters, .. }, Ok(expected)) => {
            *object_attributes == expected
                && *name_hashing_algorithm == HashingAlgorithm::Sha256
                && auth_policy.value().is_empty()
                && *parameters == PublicKeyedHashParameters::new(KeyedHashScheme::Null)
        }
        _ => false,
    }
}

/// The parts of a wrapped key.
struct Blob {
    parent: u8,
    public: Public,
    private: Private,
}

fn put_part(out: &mut Vec<u8>, part: &[u8]) -> Result<(), ProtectorError> {
    let len = u16::try_from(part.len()).map_err(|_| ProtectorError::Failing { by: NAME, detail: "a sealed part too large".into() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(part);
    Ok(())
}

fn take_part<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<2>()?;
    let len = u16::from_be_bytes(*len) as usize;
    let (part, tail) = (tail.get(..len)?, &tail[len..]);
    *rest = tail;
    Some(part)
}

impl Blob {
    fn encode(&self) -> Result<Vec<u8>, ProtectorError> {
        let public = self.public.marshall().map_err(|e| failing("marshal", e))?;
        let mut out = vec![WRAPPED_VERSION, self.parent];
        put_part(&mut out, &public)?;
        put_part(&mut out, self.private.value())?;
        Ok(out)
    }

    /// Exactly the encoding above, of a sealed object as this protector
    /// makes them; anything else won't open.
    fn decode(wrapped: &[u8]) -> Result<Blob, ProtectorError> {
        let bad = |what: &str| ProtectorError::WontOpen(format!("a TPM wrapped key with {what}"));
        let [WRAPPED_VERSION, parent, rest @ ..] = wrapped else {
            return Err(bad("an unknown version"));
        };
        let (parent, mut rest) = (*parent, rest);
        if ![PARENT_PERSISTENT, PARENT_TEMPLATE].contains(&parent) {
            return Err(bad("an unknown parent"));
        }
        let public_bytes = take_part(&mut rest).ok_or_else(|| bad("a short public part"))?;
        let private_bytes = take_part(&mut rest).ok_or_else(|| bad("a short private part"))?;
        if !rest.is_empty() {
            return Err(bad("trailing bytes"));
        }
        let public = Public::unmarshall(public_bytes).map_err(|_| bad("a public part that doesn't parse"))?;
        // Canonical: it marshals back to the same bytes.
        if public.marshall().ok().as_deref() != Some(public_bytes) {
            return Err(bad("a public part that isn't canonical"));
        }
        if !is_our_sealed_object(&public) {
            return Err(bad("a public part of another kind"));
        }
        let private = Private::try_from(private_bytes.to_vec()).map_err(|_| bad("a private part of the wrong size"))?;
        Ok(Blob { parent, public, private })
    }
}

/// An open connection to the TPM, with the parent loaded and a salted
/// session for the commands that carry the data key.
struct Open {
    ctx: Context,
    parent: KeyHandle,
    parent_kind: u8,
    session: AuthSession,
}

impl Tpm {
    pub(super) fn system() -> Self {
        Tpm { tcti: Tcti::Device }
    }

    /// A software TPM on localhost (tests only).
    #[cfg(test)]
    fn swtpm(port: u16) -> Self {
        Tpm { tcti: Tcti::Swtpm(port) }
    }

    fn context(&self) -> Result<Context, ProtectorError> {
        let conf = match &self.tcti {
            Tcti::Device => {
                use std::str::FromStr;
                TctiNameConf::Device(tss_esapi::tcti_ldr::DeviceConfig::from_str(DEVICE).map_err(|e| failing("device", e))?)
            }
            #[cfg(test)]
            Tcti::Swtpm(port) => {
                use std::str::FromStr;
                TctiNameConf::Swtpm(tss_esapi::tcti_ldr::NetworkTPMConfig::from_str(&format!("host=127.0.0.1,port={port}")).map_err(|e| failing("swtpm", e))?)
            }
        };
        Context::new(conf).map_err(|e| failing("connect", e))
    }

    /// The persistent SRK, if there is one there. A key there that isn't a
    /// storage key is failing, not passed over.
    fn persistent_srk(ctx: &mut Context) -> Result<Option<KeyHandle>, ProtectorError> {
        // Asked of the TPM's list of persistent handles first, so a TPM
        // without one doesn't log an error for the common case.
        let (listed, _) = ctx
            .execute_without_session(|c| c.get_capability(CapabilityType::Handles, SRK_HANDLE, 1))
            .map_err(|e| failing("list persistent keys", e))?;
        let there = matches!(listed, CapabilityData::Handles(ref list) if list.iter().any(|h| u32::from(*h) == SRK_HANDLE));
        if !there {
            return Ok(None);
        }
        let handle = PersistentTpmHandle::new(SRK_HANDLE).map_err(|e| failing("SRK handle", e))?;
        let object = match ctx.execute_without_session(|c| c.tr_from_tpm_public(TpmHandle::Persistent(handle))) {
            Ok(o) => o,
            // Evicted between the two calls.
            Err(e) if is_no_object(&e) => return Ok(None),
            Err(e) => return Err(failing("read the SRK", e)),
        };
        let key = KeyHandle::from(object);
        let (public, _, _) = ctx.execute_without_session(|c| c.read_public(key)).map_err(|e| failing("read the SRK", e))?;
        if !is_storage_key(&public) {
            return Err(ProtectorError::Failing { by: NAME, detail: "the key at 0x81000001 is not a storage key".into() });
        }
        Ok(Some(key))
    }

    /// The template primary, in the owner hierarchy. An owner hierarchy
    /// with an auth value set refuses this: failing.
    fn template_primary(ctx: &mut Context) -> Result<KeyHandle, ProtectorError> {
        let template = srk_template().map_err(|e| failing("template", e))?;
        ctx.execute_with_nullauth_session(|c| c.create_primary(Hierarchy::Owner, template, None, None, None, None))
            .map(|r| r.key_handle)
            .map_err(|e| failing("create the primary key", e))
    }

    /// Open the TPM with the parent `want` (or, for a new seal, the best one
    /// there) and a session salted to it.
    fn open(&self, want: Option<u8>) -> Result<Open, ProtectorError> {
        let mut ctx = self.context()?;
        let (parent, parent_kind) = match want {
            Some(PARENT_PERSISTENT) => (
                Self::persistent_srk(&mut ctx)?
                    .ok_or_else(|| ProtectorError::Failing { by: NAME, detail: "the SRK at 0x81000001 is gone".into() })?,
                PARENT_PERSISTENT,
            ),
            Some(_) => (Self::template_primary(&mut ctx)?, PARENT_TEMPLATE),
            None => match Self::persistent_srk(&mut ctx)? {
                Some(k) => (k, PARENT_PERSISTENT),
                None => (Self::template_primary(&mut ctx)?, PARENT_TEMPLATE),
            },
        };
        let session = ctx
            .execute_without_session(|c| {
                c.start_auth_session(Some(parent), None, None, SessionType::Hmac, SymmetricDefinition::AES_128_CFB, HashingAlgorithm::Sha256)
            })
            .map_err(|e| failing("session", e))?
            .ok_or_else(|| ProtectorError::Failing { by: NAME, detail: "no session".into() })?;
        Ok(Open { ctx, parent, parent_kind, session })
    }
}

impl Open {
    /// Set the session's parameter encryption: `decrypt` for a command
    /// whose first parameter carries the secret in, `encrypt` for a
    /// response that carries it out.
    fn encrypting(&mut self, decrypt: bool, encrypt: bool) -> Result<(), ProtectorError> {
        let (attrs, mask) = SessionAttributesBuilder::new().with_continue_session(true).with_decrypt(decrypt).with_encrypt(encrypt).build();
        self.ctx.tr_sess_set_attributes(self.session, attrs, mask).map_err(|e| failing("session", e))
    }

    fn seal(&mut self, key: &[u8; 32]) -> Result<Blob, ProtectorError> {
        self.encrypting(true, false)?;
        let data = SensitiveData::try_from(key.to_vec()).map_err(|e| failing("data", e))?;
        let template = sealed_template().map_err(|e| failing("template", e))?;
        let (parent, session) = (self.parent, self.session);
        let created = self
            .ctx
            .execute_with_session(Some(session), |c| c.create(parent, template, None, Some(data), None, None))
            .map_err(|e| failing("seal", e))?;
        Ok(Blob { parent: self.parent_kind, public: created.out_public, private: created.out_private })
    }

    fn unseal(&mut self, blob: Blob) -> Result<DataKey, ProtectorError> {
        self.encrypting(true, false)?;
        let (parent, session) = (self.parent, self.session);
        let loaded = match self.ctx.execute_with_session(Some(session), |c| c.load(parent, blob.private, blob.public)) {
            Ok(h) => h,
            Err(e) if is_bad_blob(&e) => return Err(ProtectorError::WontOpen(format!("this TPM refuses the sealed key: {e}"))),
            Err(e) => return Err(failing("load", e)),
        };
        // Unseal takes no parameter in; its response carries the key out.
        let unsealed = self.encrypting(false, true).and_then(|()| {
            self.ctx.execute_with_session(Some(session), |c| c.unseal(ObjectHandle::from(loaded))).map_err(|e| failing("unseal", e))
        });
        if let Err(e) = self.ctx.flush_context(ObjectHandle::from(loaded)) {
            log::warn!("protector tpm: flush: {e}");
        }
        let unsealed = unsealed?;
        let secret = Zeroizing::new(unsealed.value().to_vec());
        if secret.len() != 32 {
            return Err(ProtectorError::WontOpen(format!("a sealed key of {} bytes", secret.len())));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&secret);
        Ok(key)
    }
}

impl Protector for Tpm {
    fn id(&self) -> &'static str {
        "tpm"
    }
    fn availability(&self) -> Availability {
        match self.tcti {
            Tcti::Device => device_availability(std::fs::OpenOptions::new().read(true).write(true).open(DEVICE).map(drop)),
            #[cfg(test)]
            Tcti::Swtpm(_) => Availability::Present,
        }
    }
    /// The parent can be had (an owner hierarchy with an auth value fails
    /// here) and a salted session started. Nothing is kept: the context's
    /// end flushes the transient primary and the session.
    fn probe(&self) -> Result<(), ProtectorError> {
        self.open(None).map(drop)
    }
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, ProtectorError> {
        let mut open = self.open(None)?;
        let blob = open.seal(key)?;
        let wrapped = blob.encode()?;
        // Read back: the pairing is saved only under a key this TPM opens.
        let back = open.unseal(Blob::decode(&wrapped)?)?;
        if back.as_slice() != key.as_slice() {
            return Err(ProtectorError::Failing { by: NAME, detail: "the sealed key read back differs".into() });
        }
        Ok(wrapped)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<DataKey, ProtectorError> {
        let blob = Blob::decode(wrapped)?;
        let mut open = self.open(Some(blob.parent))?;
        open.unseal(blob)
    }
    fn remove_external(&self) -> Result<(), ProtectorError> {
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    #[test]
    fn only_enoent_and_eacces_are_absent() {
        let os = io::Error::from_raw_os_error;
        assert_eq!(device_availability(Err(os(libc::ENOENT))), Availability::Absent("no /dev/tpmrm0"));
        assert_eq!(device_availability(Err(os(libc::EACCES))), Availability::Absent("/dev/tpmrm0 isn't usable by this user"));
        for errno in [libc::EBUSY, libc::EPERM, libc::ENXIO, libc::ENODEV, libc::EIO] {
            assert_eq!(device_availability(Err(os(errno))), Availability::Present, "errno {errno}");
        }
        assert_eq!(device_availability(Ok(())), Availability::Present);
    }

    #[test]
    fn a_wrapped_key_that_doesnt_parse_wont_open() {
        for bad in [&b""[..], &[1], &[2, 2, 0, 0, 0, 0], &[1, 3, 0, 0, 0, 0], &[1, 2, 0, 5, 1], &[1, 2, 0, 0, 0, 0], &[1, 2, 0, 0, 0, 0, 9]] {
            assert!(matches!(Blob::decode(bad), Err(ProtectorError::WontOpen(_))), "{bad:?}");
        }
        // A well-formed public part of another kind (the SRK template).
        let srk = srk_template().unwrap().marshall().unwrap();
        let mut w = vec![1, 2];
        w.extend_from_slice(&(srk.len() as u16).to_be_bytes());
        w.extend_from_slice(&srk);
        w.extend_from_slice(&[0, 0]);
        assert!(matches!(Blob::decode(&w), Err(ProtectorError::WontOpen(_))));
    }

    #[test]
    fn the_sealed_template_is_recognised_and_policy_free() {
        let t = sealed_template().unwrap();
        assert!(is_our_sealed_object(&t));
        assert!(!is_storage_key(&t));
        assert!(is_storage_key(&srk_template().unwrap()));
        assert!(t.auth_policy().value().is_empty(), "no PCR or other policy");
        assert!(!t.object_attributes().sensitive_data_origin(), "the data key is ours, not the TPM's");
    }

    /// A running `swtpm`, killed on drop.
    pub(in crate::credential) struct Swtpm {
        child: Child,
        port: u16,
        _state: tempfile::TempDir,
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn free_port_pair() -> u16 {
        loop {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
                return port;
            }
        }
    }

    impl Swtpm {
        pub(in crate::credential) fn start() -> Swtpm {
            let state = tempfile::tempdir().unwrap();
            for _ in 0..5 {
                let port = free_port_pair();
                let mut child = Command::new("swtpm")
                    .args(["socket", "--tpm2"])
                    .args(["--server", &format!("type=tcp,port={port}")])
                    .args(["--ctrl", &format!("type=tcp,port={}", port + 1)])
                    .args(["--tpmstate", &format!("dir={}", state.path().display())])
                    .args(["--flags", "not-need-init,startup-clear"])
                    .spawn()
                    .expect("swtpm (apt install swtpm)");
                let deadline = Instant::now() + Duration::from_secs(10);
                while Instant::now() < deadline {
                    if let Ok(Some(_)) = child.try_wait() {
                        break; // a port taken meanwhile: try another
                    }
                    if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                        return Swtpm { child, port, _state: state };
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
            panic!("swtpm didn't start");
        }

        pub(in crate::credential) fn protector(&self) -> Tpm {
            Tpm::swtpm(self.port)
        }

        fn context(&self) -> Context {
            self.protector().context().unwrap()
        }
    }

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        k
    }

    #[test]
    #[ignore = "needs swtpm; CI runs it"]
    fn tpm_round_trip_against_swtpm() {
        let tpm = Swtpm::start();
        let p = tpm.protector();
        assert_eq!(p.availability(), Availability::Present);
        p.probe().unwrap();
        let wrapped = p.wrap(&key(1)).unwrap();
        assert_eq!(wrapped[..2], [WRAPPED_VERSION, PARENT_TEMPLATE], "no SRK on a fresh swtpm: the template primary");
        assert_eq!(*p.unwrap(&wrapped).unwrap(), key(1));
        // A second key seals separately.
        let other = p.wrap(&key(2)).unwrap();
        assert_ne!(other, wrapped);
        assert_eq!(*p.unwrap(&other).unwrap(), key(2));
        // Nothing kept outside the file.
        p.remove_external().unwrap();
        assert_eq!(*p.unwrap(&wrapped).unwrap(), key(1), "and removing nothing changed nothing");
        // A garbled private part: this TPM refuses it, won't open.
        let mut garbled = wrapped.clone();
        let last = garbled.len() - 1;
        garbled[last] ^= 1;
        assert!(matches!(p.unwrap(&garbled), Err(ProtectorError::WontOpen(_))));
        // A truncated one doesn't even parse.
        assert!(matches!(p.unwrap(&wrapped[..wrapped.len() - 1]), Err(ProtectorError::WontOpen(_))));
    }

    #[test]
    #[ignore = "needs swtpm; CI runs it"]
    fn tpm_uses_the_persistent_srk_when_there() {
        use tss_esapi::interface_types::dynamic_handles::Persistent;
        use tss_esapi::interface_types::resource_handles::Provision;
        let tpm = Swtpm::start();
        let p = tpm.protector();
        let before = p.wrap(&key(3)).unwrap();
        // Make the template key persistent at 0x81000001, as provisioning
        // tools do.
        let mut ctx = tpm.context();
        let primary = Tpm::template_primary(&mut ctx).unwrap();
        let handle = PersistentTpmHandle::new(SRK_HANDLE).unwrap();
        ctx.execute_with_nullauth_session(|c| c.evict_control(Provision::Owner, primary.into(), Persistent::Persistent(handle))).unwrap();
        drop(ctx);
        let after = p.wrap(&key(4)).unwrap();
        assert_eq!(after[1], PARENT_PERSISTENT);
        assert_eq!(*p.unwrap(&after).unwrap(), key(4));
        // The earlier seal still opens under the template primary it names.
        assert_eq!(before[1], PARENT_TEMPLATE);
        assert_eq!(*p.unwrap(&before).unwrap(), key(3));
    }

    /// Copy refusal: a key sealed by one TPM doesn't open on another.
    #[test]
    #[ignore = "needs swtpm; CI runs it"]
    fn tpm_a_blob_from_another_tpm_wont_open() {
        let (first, second) = (Swtpm::start(), Swtpm::start());
        let wrapped = first.protector().wrap(&key(5)).unwrap();
        match second.protector().unwrap(&wrapped) {
            Err(ProtectorError::WontOpen(_)) => {}
            other => panic!("expected won't open, got {:?}", other.map(|_| "a key")),
        }
        assert_eq!(*first.protector().unwrap(&wrapped).unwrap(), key(5), "it still opens where it was sealed");
    }

    /// An owner hierarchy with an auth value set: the TPM is there, so that
    /// is failing, never absent.
    #[test]
    #[ignore = "needs swtpm; CI runs it"]
    fn tpm_an_owner_auth_value_is_failing() {
        use tss_esapi::handles::AuthHandle;
        use tss_esapi::structures::Auth;
        let tpm = Swtpm::start();
        let mut ctx = tpm.context();
        ctx.execute_with_nullauth_session(|c| c.hierarchy_change_auth(AuthHandle::Owner, Auth::try_from(b"owner-set".to_vec()).unwrap()))
            .unwrap();
        drop(ctx);
        let p = tpm.protector();
        assert_eq!(p.availability(), Availability::Present);
        assert!(matches!(p.probe(), Err(ProtectorError::Failing { by: NAME, .. })));
        assert!(matches!(p.wrap(&key(6)), Err(ProtectorError::Failing { by: NAME, .. })));
    }
}
