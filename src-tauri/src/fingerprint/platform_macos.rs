//! macOS-specific machine fingerprinting for platform binding.
//!
//! Collects five machine attributes (hostname, machine UUID, CPU brand, disk serial,
//! MAC address) and uses the same MachineAttributes/fingerprint types as Linux.

use std::process::Command;

// Re-export shared types from platform_linux (they're platform-agnostic)
pub use super::platform_linux::{
    compute_machine_fingerprint, compute_machine_fingerprint_hex, four_of_five_combinations,
    FingerprintError, MachineAttributes,
};

/// Collect machine identity attributes from macOS.
///
/// Sources:
/// - hostname: gethostname (same as Linux)
/// - machine_id: IOPlatformUUID via ioreg
/// - cpu: sysctl machdep.cpu.brand_string
/// - disk_serial: diskutil info disk0 (system disk)
/// - mac_address: first non-loopback interface via ifconfig
pub fn collect_machine_attributes_macos() -> Result<MachineAttributes, FingerprintError> {
    Ok(MachineAttributes {
        hostname: collect_hostname(),
        machine_id: collect_machine_uuid(),
        cpu: collect_cpu_brand(),
        disk_serial: collect_disk_serial(),
        mac_address: collect_mac_address(),
    })
}

/// Hostname via the hostname crate (cross-platform).
fn collect_hostname() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().trim().to_string())
        .unwrap_or_default()
}

/// IOPlatformUUID — the macOS equivalent of /etc/machine-id.
/// Reads from: ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID
fn collect_machine_uuid() -> String {
    let output = match Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("IOPlatformUUID") {
            // Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
            if let Some(uuid) = line.split('"').nth(3) {
                return uuid.trim().to_string();
            }
        }
    }
    String::new()
}

/// CPU brand string via sysctl.
fn collect_cpu_brand() -> String {
    let output = match Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Disk serial from the system disk (disk0).
/// Uses: diskutil info disk0 | grep "Serial Number"
fn collect_disk_serial() -> String {
    let output = match Command::new("diskutil")
        .args(["info", "disk0"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Device / Media Name:") || trimmed.starts_with("Media Name:") {
            if let Some((_key, value)) = trimmed.split_once(':') {
                return value.trim().to_string();
            }
        }
    }
    String::new()
}

/// First non-loopback MAC address via ifconfig.
fn collect_mac_address() -> String {
    let output = match Command::new("ifconfig").output() {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();

    for line in stdout.lines() {
        // Interface header: "en0: flags=..."
        if !line.starts_with('\t') && !line.starts_with(' ') {
            if let Some(name) = line.split(':').next() {
                current_iface = name.to_string();
            }
        }

        // Skip loopback
        if current_iface == "lo0" {
            continue;
        }

        // Look for "ether XX:XX:XX:XX:XX:XX"
        let trimmed = line.trim();
        if trimmed.starts_with("ether ") {
            let mac = trimmed.strip_prefix("ether ").unwrap_or("").trim();
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                return mac.to_string();
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_hostname_non_empty() {
        let h = collect_hostname();
        assert!(!h.is_empty(), "hostname should not be empty on macOS");
    }

    #[test]
    fn test_collect_machine_uuid() {
        let uuid = collect_machine_uuid();
        // Should be a UUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
        if !uuid.is_empty() {
            assert!(uuid.contains('-'), "UUID should contain dashes: {}", uuid);
        }
    }

    #[test]
    fn test_collect_cpu_brand() {
        let cpu = collect_cpu_brand();
        assert!(!cpu.is_empty(), "CPU brand should not be empty on macOS");
    }

    #[test]
    fn test_collect_mac_address() {
        let mac = collect_mac_address();
        if !mac.is_empty() {
            assert!(mac.contains(':'), "MAC should contain colons: {}", mac);
        }
    }

    #[test]
    fn test_collect_all_attributes() {
        let attrs = collect_machine_attributes_macos().expect("should succeed on macOS");
        assert!(
            attrs.attribute_count() >= 3,
            "should have at least 3 attributes, got {}",
            attrs.attribute_count(),
        );
    }
}
