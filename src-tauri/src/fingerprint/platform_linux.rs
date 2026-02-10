//! Linux-specific machine fingerprinting for platform binding.
//!
//! Collects five machine attributes (hostname, machine-id, CPU, disk serial, MAC address)
//! and computes an HMAC-SHA256 fingerprint used to bind encrypted credentials to a
//! specific machine. This is the desktop equivalent of the agent connector's fingerprint,
//! using a distinct HMAC domain label ("vettid-desktop-platform-v1").

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

/// Generate all 5 possible 4-of-5 attribute combinations.
///
/// Each combination omits one attribute (set to empty string).
/// Order: hostname, machine_id, cpu, disk, mac -- matching the Go agent connector.
///
/// Used for tolerance: if the full fingerprint fails decryption, each 4-of-5
/// combination is tried. This allows credentials to survive a single hardware
/// change (e.g., NIC replacement, hostname change).
pub fn four_of_five_combinations(attrs: &MachineAttributes) -> Vec<MachineAttributes> {
    let mut combos = Vec::with_capacity(5);

    // Omit hostname
    combos.push(MachineAttributes {
        hostname: String::new(),
        machine_id: attrs.machine_id.clone(),
        cpu: attrs.cpu.clone(),
        disk_serial: attrs.disk_serial.clone(),
        mac_address: attrs.mac_address.clone(),
    });

    // Omit machine_id
    combos.push(MachineAttributes {
        hostname: attrs.hostname.clone(),
        machine_id: String::new(),
        cpu: attrs.cpu.clone(),
        disk_serial: attrs.disk_serial.clone(),
        mac_address: attrs.mac_address.clone(),
    });

    // Omit cpu
    combos.push(MachineAttributes {
        hostname: attrs.hostname.clone(),
        machine_id: attrs.machine_id.clone(),
        cpu: String::new(),
        disk_serial: attrs.disk_serial.clone(),
        mac_address: attrs.mac_address.clone(),
    });

    // Omit disk_serial
    combos.push(MachineAttributes {
        hostname: attrs.hostname.clone(),
        machine_id: attrs.machine_id.clone(),
        cpu: attrs.cpu.clone(),
        disk_serial: String::new(),
        mac_address: attrs.mac_address.clone(),
    });

    // Omit mac_address
    combos.push(MachineAttributes {
        hostname: attrs.hostname.clone(),
        machine_id: attrs.machine_id.clone(),
        cpu: attrs.cpu.clone(),
        disk_serial: attrs.disk_serial.clone(),
        mac_address: String::new(),
    });

    combos
}

// --- Internal helpers ---

fn compute_fingerprint_from_fields(fields: &BTreeMap<&str, &str>) -> [u8; 32] {
    // BTreeMap iterates in sorted key order, matching Go's sort.Strings
    let parts: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect();
    let data = parts.join("\n");

    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(PLATFORM_KEY_LABEL.as_bytes()).expect("HMAC accepts any key size");
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
    fn test_four_of_five_generates_five_variants() {
        let attrs = MachineAttributes {
            hostname: "host".to_string(),
            machine_id: "mid".to_string(),
            cpu: "cpu".to_string(),
            disk_serial: "disk".to_string(),
            mac_address: "mac".to_string(),
        };
        let combos = four_of_five_combinations(&attrs);
        assert_eq!(combos.len(), 5);

        // Each combo should have exactly 4 non-empty attributes
        for combo in &combos {
            assert_eq!(combo.attribute_count(), 4);
        }

        // Verify which attribute is omitted in each
        assert!(combos[0].hostname.is_empty());
        assert!(combos[1].machine_id.is_empty());
        assert!(combos[2].cpu.is_empty());
        assert!(combos[3].disk_serial.is_empty());
        assert!(combos[4].mac_address.is_empty());
    }

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
