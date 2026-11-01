//! Linux-specific machine fingerprinting for platform binding.
//!
//! Collects five machine attributes (hostname, machine-id, CPU, disk serial, MAC address)
//! and computes the HMAC-SHA256 machine fingerprint, shown in Settings and sent at pairing.
//! This is the desktop equivalent of the agent connector's fingerprint, using a distinct
//! HMAC domain label ("vettid-desktop-platform-v1"). The saved pairing is bound to the
//! machine id alone (#14): see `compute_machine_bound_key` and `compute_storage_binding`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::Command;

/// HMAC domain label for desktop platform fingerprints.
/// NOTE: This is intentionally different from the agent connector which uses
/// "vettid-agent-platform-v1". Different domain labels ensure that an agent
/// credential store cannot be opened by the desktop app and vice versa.
const PLATFORM_KEY_LABEL: &str = "vettid-desktop-platform-v1";

/// HMAC domain label for the machine-bound storage key (the credential
/// store's fallback when the OS keyring is unavailable).
///
/// SECURITY: must differ from `PLATFORM_KEY_LABEL`. The fingerprint computed
/// under that label is public: it is shown in Settings and sent to the vault
/// at pairing. A key computed under the same label would be that same value.
///
/// v2 (#14, owner decision (a), 2026-11-01): the key is computed from the
/// machine id alone. v1 covered all five attributes; files sealed under it
/// no longer open and are reported as unreadable.
const MACHINE_BOUND_KEY_LABEL: &str = "vettid-desktop-machine-bound-key-v2";

/// HMAC domain label for the storage binding: the machine value the
/// credential store mixes into its AEAD associated data (#14, owner
/// decision (a), 2026-11-01). Must differ from the other two labels.
const STORAGE_BINDING_LABEL: &str = "vettid-desktop-storage-binding-v1";

/// Virtual network interface prefixes to skip when collecting MAC addresses.
/// These are created by container runtimes and virtualization tools and are
/// not stable machine identifiers.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &["veth", "docker", "br-", "virbr", "vnet"];

/// Errors that can occur during fingerprint collection or computation.
#[derive(Debug, Clone)]
pub enum FingerprintError {
    /// A required system resource could not be read.
    CollectionFailed(String),
    /// Insufficient machine attributes for a reliable fingerprint.
    InsufficientAttributes { found: usize, required: usize },
    /// The binary could not be hashed.
    BinaryHashFailed(String),
    /// The machine id is empty or a placeholder. The saved pairing is bound
    /// to it (the storage binding and the machine-bound key, #14), so
    /// nothing can be saved or opened without it.
    MissingMachineId,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FingerprintError::CollectionFailed(msg) => {
                write!(f, "fingerprint collection failed: {}", msg)
            }
            FingerprintError::InsufficientAttributes { found, required } => {
                write!(
                    f,
                    "insufficient machine attributes ({}/{}): cannot derive platform key",
                    found, required
                )
            }
            FingerprintError::MissingMachineId => f.write_str(
                "this computer has no usable machine id",
            ),
            FingerprintError::BinaryHashFailed(msg) => {
                write!(f, "binary hash failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for FingerprintError {}

/// The five machine identity attributes used for fingerprinting.
///
/// Each attribute is collected on a best-effort basis; empty strings indicate
/// that an attribute could not be read. At least 3 of 5 must be non-empty
/// for a reliable fingerprint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachineAttributes {
    pub hostname: String,
    pub machine_id: String,
    pub cpu: String,
    pub disk_serial: String,
    pub mac_address: String,
}

impl MachineAttributes {
    /// Returns the number of non-empty attributes.
    pub fn attribute_count(&self) -> usize {
        let mut count = 0;
        if !self.hostname.is_empty() {
            count += 1;
        }
        if !self.machine_id.is_empty() {
            count += 1;
        }
        if !self.cpu.is_empty() {
            count += 1;
        }
        if !self.disk_serial.is_empty() {
            count += 1;
        }
        if !self.mac_address.is_empty() {
            count += 1;
        }
        count
    }

    /// Returns the attributes as a map for fingerprint computation.
    /// Keys match the canonical names used in the Go agent connector.
    pub fn fields(&self) -> BTreeMap<&'static str, &str> {
        let mut m = BTreeMap::new();
        m.insert("hostname", self.hostname.as_str());
        m.insert("machine_id", self.machine_id.as_str());
        m.insert("cpu", self.cpu.as_str());
        m.insert("disk", self.disk_serial.as_str());
        m.insert("mac", self.mac_address.as_str());
        m
    }
}

/// Collect machine identity attributes from the local Linux system.
///
/// Gathers hostname, machine-id, CPU model, disk serial, and MAC address.
/// Each attribute is best-effort; failures are silently returned as empty strings
/// rather than propagating errors.
pub fn collect_machine_attributes() -> Result<MachineAttributes, FingerprintError> {
    let hostname = collect_hostname();
    let machine_id = collect_machine_id();
    let cpu = collect_linux_cpu();
    let disk_serial = collect_linux_disk_serial();
    let mac_address = collect_linux_mac();

    Ok(MachineAttributes {
        hostname,
        machine_id,
        cpu,
        disk_serial,
        mac_address,
    })
}

/// Compute the HMAC-SHA256 fingerprint from machine attributes.
///
/// The canonical format:
/// 1. Create key:value pairs from the attributes map
/// 2. Sort alphabetically by key (BTreeMap handles this)
/// 3. Join as "key:value\n..." (e.g., "cpu:Intel...\ndisk:WD-...\nhostname:myhost\nmac:aa:bb:...\nmachine_id:abc123")
/// 4. HMAC-SHA256 with key "vettid-desktop-platform-v1"
///
/// This matches the Go agent connector's `computeFingerprintFromFields` exactly,
/// except for the HMAC key (which uses "vettid-agent-platform-v1" in the agent).
pub fn compute_machine_fingerprint(attrs: &MachineAttributes) -> [u8; 32] {
    compute_fingerprint_from_fields(&attrs.fields())
}

/// Returns the hex-encoded fingerprint string.
pub fn compute_machine_fingerprint_hex(attrs: &MachineAttributes) -> String {
    hex::encode(compute_machine_fingerprint(attrs))
}

/// Compute the machine-bound storage key from the machine id (#14).
///
/// Only the machine id goes in, trimmed, in the same canonical `name:value`
/// form as the fingerprint, under its own HMAC label. The other attributes
/// (hostname, CPU, disk serial, MAC) add no secrecy that the machine id
/// doesn't already give, and they change: a hostname from DHCP, a dock's
/// MAC, a USB disk that enumerates first. Each change used to lock the
/// person out of the saved pairing.
///
/// SECURITY: the result is key material. Never display, log or send it.
/// The caller ([`super::platform_key::machine_bound_key_from`]) refuses an
/// empty or placeholder machine id.
pub fn compute_machine_bound_key(attrs: &MachineAttributes) -> [u8; 32] {
    let mut fields = BTreeMap::new();
    fields.insert("machine_id", attrs.machine_id.trim());
    hmac_fields(MACHINE_BOUND_KEY_LABEL, &fields)
}

/// Compute the storage binding from the machine id: the value the
/// credential store mixes into its AEAD associated data, so a saved pairing
/// opens only on the machine that wrote it (#14).
///
/// Only the machine id goes in, like the machine-bound key, but under its
/// own label: the hostname, CPU, disk serial and MAC change (a rename, a
/// dock, a USB disk), and each change used to lock the person out.
pub fn compute_storage_binding(attrs: &MachineAttributes) -> [u8; 32] {
    let mut fields = BTreeMap::new();
    fields.insert("machine_id", attrs.machine_id.trim());
    hmac_fields(STORAGE_BINDING_LABEL, &fields)
}

// --- Internal helpers ---

fn compute_fingerprint_from_fields(fields: &BTreeMap<&str, &str>) -> [u8; 32] {
    hmac_fields(PLATFORM_KEY_LABEL, fields)
}

fn hmac_fields(label: &str, fields: &BTreeMap<&str, &str>) -> [u8; 32] {
    // BTreeMap iterates in sorted key order, matching Go's sort.Strings
    let parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect();
    let data = parts.join("\n");

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(label.as_bytes()).expect("HMAC accepts any key size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Collect hostname using std::env (gethostname).
fn collect_hostname() -> String {
    match hostname::get() {
        Ok(name) => name.to_string_lossy().trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Read /etc/machine-id and trim whitespace.
fn collect_machine_id() -> String {
    match fs::read_to_string("/etc/machine-id") {
        Ok(content) => content.trim().to_string(),
        Err(_) => String::new(),
    }
}

/// Parse /proc/cpuinfo for the first "model name" field value.
fn collect_linux_cpu() -> String {
    let file = match fs::File::open("/proc/cpuinfo") {
        Ok(f) => f,
        Err(_) => return String::new(),
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.starts_with("model name") {
            if let Some((_key, value)) = line.split_once(':') {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

/// Collect disk serial via lsblk.
///
/// Try /dev/sda first, then /dev/nvme0n1, then fall back to finding the first
/// disk with a serial number.
fn collect_linux_disk_serial() -> String {
    // Try /dev/sda
    if let Some(serial) = try_lsblk_serial("/dev/sda") {
        return serial;
    }

    // Try /dev/nvme0n1 (common on modern systems with NVMe SSDs)
    if let Some(serial) = try_lsblk_serial("/dev/nvme0n1") {
        return serial;
    }

    // Fallback: find the first disk with a serial
    if let Ok(output) = Command::new("lsblk")
        .args(["--nodeps", "-o", "NAME,SERIAL", "-n"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && !fields[1].is_empty() {
                return fields[1].to_string();
            }
        }
    }

    String::new()
}

/// Try to read the serial for a specific block device.
fn try_lsblk_serial(device: &str) -> Option<String> {
    let output = Command::new("lsblk")
        .args(["--nodeps", "-o", "SERIAL", "-n", device])
        .output()
        .ok()?;
    let serial = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if serial.is_empty() {
        None
    } else {
        Some(serial)
    }
}

/// Collect the first non-loopback, non-virtual network interface MAC address.
///
/// Skips interfaces that are:
/// - Loopback (lo)
/// - Virtual (veth*, docker*, br-*, virbr*, vnet*)
/// - Have no hardware address
///
/// Reads from /sys/class/net/ which is available on all Linux systems.
fn collect_linux_mac() -> String {
    let net_dir = match fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    let mut ifaces: Vec<String> = net_dir
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    // Sort for deterministic ordering
    ifaces.sort();

    for iface in ifaces {
        // Skip loopback
        if iface == "lo" {
            continue;
        }

        // Skip virtual interfaces
        if VIRTUAL_IFACE_PREFIXES
            .iter()
            .any(|prefix| iface.starts_with(prefix))
        {
            continue;
        }

        // Read the MAC address from sysfs
        let addr_path = format!("/sys/class/net/{}/address", iface);
        if let Ok(mac) = fs::read_to_string(&addr_path) {
            let mac = mac.trim().to_string();
            // Skip empty or all-zero MACs (e.g., 00:00:00:00:00:00)
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                return mac;
            }
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_count_all_populated() {
        let attrs = MachineAttributes {
            hostname: "myhost".to_string(),
            machine_id: "abc123".to_string(),
            cpu: "Intel Core i7".to_string(),
            disk_serial: "WD-12345".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        assert_eq!(attrs.attribute_count(), 5);
    }

    #[test]
    fn test_attribute_count_some_empty() {
        let attrs = MachineAttributes {
            hostname: "myhost".to_string(),
            machine_id: String::new(),
            cpu: "Intel Core i7".to_string(),
            disk_serial: String::new(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        assert_eq!(attrs.attribute_count(), 3);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "test-machine-id".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let fp1 = compute_machine_fingerprint(&attrs);
        let fp2 = compute_machine_fingerprint(&attrs);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_changes_with_different_attrs() {
        let attrs1 = MachineAttributes {
            hostname: "host1".to_string(),
            machine_id: "id1".to_string(),
            cpu: "cpu1".to_string(),
            disk_serial: "disk1".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let attrs2 = MachineAttributes {
            hostname: "host2".to_string(),
            machine_id: "id1".to_string(),
            cpu: "cpu1".to_string(),
            disk_serial: "disk1".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let fp1 = compute_machine_fingerprint(&attrs1);
        let fp2 = compute_machine_fingerprint(&attrs2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_machine_bound_key_differs_from_fingerprint() {
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "test-machine-id".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let key = compute_machine_bound_key(&attrs);
        assert_ne!(key, compute_machine_fingerprint(&attrs));
        assert_eq!(key, compute_machine_bound_key(&attrs));

        // Known answer for these test inputs: changing the label or the
        // canonical format would orphan every machine-bound store.
        assert_eq!(hex::encode(key), KNOWN_MACHINE_BOUND_KEY);
        // Not the v1 key (all five attributes), which no longer opens.
        assert_ne!(
            hex::encode(key),
            "a2f09ada1d061c08ff14a447c3a24c31b47096f208d3e49b67dcc7418ef85efe"
        );

        // A different machine id gives a different key.
        let mut other = attrs.clone();
        other.machine_id = "other-machine-id".to_string();
        assert_ne!(key, compute_machine_bound_key(&other));
    }

    /// #14: only the machine id goes into the machine-bound key, so the
    /// unstable attributes can change without locking the person out.
    /// Surrounding whitespace in the machine id doesn't matter either.
    #[test]
    fn test_machine_bound_key_depends_only_on_the_machine_id() {
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "test-machine-id".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let key = compute_machine_bound_key(&attrs);
        let changed = MachineAttributes {
            hostname: "dhcp-host-17".to_string(),
            machine_id: "  test-machine-id\n".to_string(),
            cpu: "Other CPU".to_string(),
            disk_serial: String::new(),
            mac_address: "11:22:33:44:55:66".to_string(),
        };
        assert_eq!(key, compute_machine_bound_key(&changed));
        // The fingerprint still covers every attribute.
        assert_ne!(compute_machine_fingerprint(&attrs), compute_machine_fingerprint(&changed));
    }

    /// The storage binding uses the machine id alone too, under its own
    /// label: not the fingerprint and not the machine-bound key.
    #[test]
    fn test_storage_binding_depends_only_on_the_machine_id_and_is_distinct() {
        let attrs = MachineAttributes {
            hostname: "testhost".to_string(),
            machine_id: "test-machine-id".to_string(),
            cpu: "Test CPU".to_string(),
            disk_serial: "TEST-SERIAL".to_string(),
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
        };
        let binding = compute_storage_binding(&attrs);
        assert_eq!(hex::encode(binding), KNOWN_STORAGE_BINDING);
        assert_ne!(binding, compute_machine_bound_key(&attrs));
        assert_ne!(binding, compute_machine_fingerprint(&attrs));
        let mut renamed = attrs.clone();
        renamed.hostname = "renamed-pc".to_string();
        renamed.mac_address = "11:22:33:44:55:66".to_string();
        assert_eq!(binding, compute_storage_binding(&renamed));
        renamed.machine_id = "other-machine-id".to_string();
        assert_ne!(binding, compute_storage_binding(&renamed));
    }

    /// The storage binding for the fixed test attributes (label
    /// `vettid-desktop-storage-binding-v1`, `machine_id:test-machine-id`).
    const KNOWN_STORAGE_BINDING: &str = "b195433bf62655ddd3f4221240424f5b367bb82ab05e5bcc9c6437b6e283cb0b";

    /// The machine-bound key for the fixed test attributes above (label v2,
    /// `machine_id:test-machine-id`).
    const KNOWN_MACHINE_BOUND_KEY: &str = "d79ccc3b3fef7b50525c4279e4dce7c28b789623259242e739f372641efa1c85";

    #[test]
    fn test_hex_encoding() {
        let attrs = MachineAttributes {
            hostname: "test".to_string(),
            machine_id: "test".to_string(),
            cpu: "test".to_string(),
            disk_serial: "test".to_string(),
            mac_address: "test".to_string(),
        };
        let hex_str = compute_machine_fingerprint_hex(&attrs);
        assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_fields_map_keys() {
        let attrs = MachineAttributes {
            hostname: "h".to_string(),
            machine_id: "m".to_string(),
            cpu: "c".to_string(),
            disk_serial: "d".to_string(),
            mac_address: "a".to_string(),
        };
        let fields = attrs.fields();
        assert_eq!(fields.len(), 5);
        assert!(fields.contains_key("hostname"));
        assert!(fields.contains_key("machine_id"));
        assert!(fields.contains_key("cpu"));
        assert!(fields.contains_key("disk"));
        assert!(fields.contains_key("mac"));
    }
}
