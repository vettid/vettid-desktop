//! Windows-specific machine fingerprinting for platform binding.
//!
//! Collects the same five machine attributes as Linux and macOS (hostname,
//! machine id, CPU brand, disk serial, MAC address) and uses the same
//! MachineAttributes/fingerprint types.
//!
//! SECURITY: every attribute is read through the registry or a Win32 call.
//! Nothing is executed, so there is no helper binary (`ioreg`, `lsblk`) that
//! a planted program earlier on PATH could impersonate.
//!
//! The exact text of each value is part of the machine-bound key. Changing
//! how a value is chosen or formatted changes the key of every Windows
//! install, so treat the rules in this file as a wire format. They match
//! the agent connector's `machine_windows.go`.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIfEntry2Ex, MibIfEntryNormalWithoutStatistics,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ENUMERATE_SUB_KEYS, KEY_WOW64_64KEY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    RRF_SUBKEY_WOW6464KEY,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::IO::DeviceIoControl;

// Re-export shared types from platform_linux (they're platform-agnostic)
pub use super::platform_linux::{
    compute_machine_fingerprint, compute_machine_fingerprint_hex, four_of_five_combinations,
    FingerprintError, MachineAttributes,
};

/// Collect machine identity attributes from Windows.
///
/// Sources:
/// - hostname: the hostname crate (same as Linux and macOS)
/// - machine_id: `MachineGuid`, generated once by Windows setup. The
///   counterpart of `/etc/machine-id`: stable across reboots and updates,
///   new after a reinstall.
/// - cpu: brand string of the first processor, from the registry
/// - disk_serial: serial number of the disk under the Windows volume, as
///   the storage driver reports it
/// - mac_address: permanent address of a physical adapter, built-in ones
///   preferred (see `choose_mac`)
///
/// Each attribute is best-effort; a failure yields an empty string.
pub fn collect_machine_attributes_windows() -> Result<MachineAttributes, FingerprintError> {
    Ok(MachineAttributes {
        hostname: collect_hostname(),
        machine_id: read_hklm_string(r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
        cpu: read_hklm_string(
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            "ProcessorNameString",
        ),
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

/// NUL-terminated UTF-16 for a Win32 call.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read one string value from the 64-bit view of HKEY_LOCAL_MACHINE.
fn read_hklm_string(subkey: &str, value: &str) -> String {
    read_reg_string(HKEY_LOCAL_MACHINE, Some(subkey), value)
}

fn read_reg_string(key: HKEY, subkey: Option<&str>, value: &str) -> String {
    let subkey_w = subkey.map(wide);
    let subkey_ptr = subkey_w.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let value_w = wide(value);
    let mut buf = [0u16; 512];
    let mut size = std::mem::size_of_val(&buf) as u32;
    // SAFETY: all pointers are to live local buffers, `size` holds the
    // buffer size in bytes, and RegGetValueW NUL-terminates REG_SZ data.
    let status = unsafe {
        RegGetValueW(
            key,
            subkey_ptr,
            value_w.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return String::new();
    }
    let chars = (size as usize / 2).min(buf.len());
    let end = buf[..chars].iter().position(|&c| c == 0).unwrap_or(chars);
    String::from_utf16_lossy(&buf[..end]).trim().to_string()
}

fn read_reg_dword(key: HKEY, value: &str) -> Option<u32> {
    let value_w = wide(value);
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `data` is a live u32 and `size` is its size in bytes.
    let status = unsafe {
        RegGetValueW(
            key,
            ptr::null(),
            value_w.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            &mut data as *mut u32 as *mut c_void,
            &mut size,
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
/// Byte offset of `SerialNumberOffset` in STORAGE_DEVICE_DESCRIPTOR.
const SERIAL_NUMBER_OFFSET_FIELD: usize = 24;

/// STORAGE_PROPERTY_QUERY with PropertyId StorageDeviceProperty (0) and
/// QueryType PropertyStandardQuery (0).
#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional_parameters: [u8; 1],
}

/// Drive of the Windows directory, e.g. `C:`. Asked of the OS, not read
/// from %SystemDrive%, which the environment can change.
fn system_drive() -> Option<String> {
    let mut buf = [0u16; 260];
    // SAFETY: `buf` is a live buffer of the stated length in characters.
    let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len < 2 || len > buf.len() {
        return None;
    }
    let dir = String::from_utf16_lossy(&buf[..len]);
    let b = dir.as_bytes();
    (b[0].is_ascii_alphabetic() && b[1] == b':').then(|| dir[..2].to_string())
}

/// Serial number of the disk that holds the Windows volume, falling back to
/// the first physical disk. Both are opened with no access rights, which is
/// enough for the query and works for a standard user.
///
/// The string is whatever the storage driver reports. The inbox NVMe driver
/// gives the drive's EUI-64, not the serial printed on the label, and a
/// vendor driver may give a different string for the same drive.
fn collect_disk_serial() -> String {
    let mut candidates = Vec::new();
    if let Some(drive) = system_drive() {
        candidates.push(format!(r"\\.\{}", drive));
    }
    candidates.push(r"\\.\PhysicalDrive0".to_string());
    candidates
        .iter()
        .map(|device| query_disk_serial(device))
        .find(|serial| !serial.is_empty())
        .unwrap_or_default()
}

fn query_disk_serial(device: &str) -> String {
    let device_w = wide(device);
    // SAFETY: `device_w` is NUL-terminated and outlives the call.
    let handle: HANDLE = unsafe {
        CreateFileW(
            device_w.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return String::new();
    }

    let query = StoragePropertyQuery {
        property_id: 0,
        query_type: 0,
        additional_parameters: [0],
    };
    let mut buf = [0u8; 1024];
    let mut returned: u32 = 0;
    // SAFETY: input and output pointers are live local buffers of the
    // stated sizes; the handle is valid until CloseHandle below.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const StoragePropertyQuery as *const c_void,
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    // SAFETY: `handle` was returned by CreateFileW and is closed once.
    unsafe { CloseHandle(handle) };

    if ok == 0 || returned as usize > buf.len() {
        return String::new();
    }
    parse_disk_serial(&buf[..returned as usize])
}

/// Extract the serial number from a STORAGE_DEVICE_DESCRIPTOR. Returns an
/// empty string when the device reports none, when the descriptor is
/// truncated, or when the serial is a placeholder.
fn parse_disk_serial(data: &[u8]) -> String {
    if data.len() < SERIAL_NUMBER_OFFSET_FIELD + 4 {
        return String::new();
    }
    let offset = u32::from_le_bytes([
        data[SERIAL_NUMBER_OFFSET_FIELD],
        data[SERIAL_NUMBER_OFFSET_FIELD + 1],
        data[SERIAL_NUMBER_OFFSET_FIELD + 2],
        data[SERIAL_NUMBER_OFFSET_FIELD + 3],
    ]) as usize;
    // Zero means the device reports no serial number.
    if offset == 0 || offset >= data.len() {
        return String::new();
    }
    // No terminator means the string was cut off.
    let Some(len) = data[offset..].iter().position(|&b| b == 0) else {
        return String::new();
    };
    let serial = String::from_utf8_lossy(&data[offset..offset + len])
        .trim()
        .to_string();
    if is_placeholder_serial(&serial) {
        return String::new();
    }
    serial
}

/// A serial that carries no identity: only zeros and separators, which is
/// what a drive without an EUI-64 reports and many units share.
fn is_placeholder_serial(serial: &str) -> bool {
    serial.chars().all(|c| matches!(c, '0' | '_' | '.' | '-' | ' '))
}

const NET_ADAPTER_CLASS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
/// NCF_PHYSICAL: the adapter is a physical device, not a virtual one.
const NCF_PHYSICAL: u32 = 0x4;
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_IEEE80211: u32 = 71;
const AF_UNSPEC: u32 = 0;

/// The network adapters Windows marks as physical: instance GUID (upper
/// case, with braces) and whether the adapter is built in. Virtual switches,
/// VPN adapters and the WSL and Hyper-V adapters are not marked, and they
/// come and go, which would change the fingerprint.
fn physical_adapters() -> Vec<(String, bool)> {
    let mut guids = Vec::new();
    let class_w = wide(NET_ADAPTER_CLASS_KEY);
    let mut class_key: HKEY = ptr::null_mut();
    // SAFETY: `class_w` is NUL-terminated; `class_key` receives the handle.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            class_w.as_ptr(),
            0,
            KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
            &mut class_key,
        )
    };
    if status != ERROR_SUCCESS {
        return guids;
    }

    for index in 0u32.. {
        let mut name = [0u16; 64];
        let mut name_len = name.len() as u32;
        // SAFETY: `name` is a live buffer of `name_len` characters.
        let status = unsafe {
            RegEnumKeyExW(
                class_key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            // ERROR_NO_MORE_ITEMS, or a subkey name we cannot hold.
            break;
        }
        let subkey = String::from_utf16_lossy(&name[..name_len as usize]);
        let path = format!(r"{}\{}", NET_ADAPTER_CLASS_KEY, subkey);
        if let Some(adapter) = physical_adapter_at(&path) {
            guids.push(adapter);
        }
    }
    // SAFETY: `class_key` was opened above and is closed once.
    unsafe { RegCloseKey(class_key) };
    guids
}

/// The adapter's instance GUID, and whether it is built in, if `path`
/// describes a physical adapter. Built in means on the PCI bus: soldered or
/// in an internal slot, as opposed to a USB or dock adapter.
fn physical_adapter_at(path: &str) -> Option<(String, bool)> {
    let path_w = wide(path);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: `path_w` is NUL-terminated; `key` receives the handle.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path_w.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        // "Properties" and similar subkeys are not readable; skip.
        return None;
    }
    let characteristics = read_reg_dword(key, "Characteristics");
    let guid = read_reg_string(key, None, "NetCfgInstanceId");
    let instance = read_reg_string(key, None, "DeviceInstanceID");
    // SAFETY: `key` was opened above and is closed once.
    unsafe { RegCloseKey(key) };

    match characteristics {
        Some(c) if c & NCF_PHYSICAL != 0 && !guid.is_empty() => Some((
            guid.to_uppercase(),
            instance.to_uppercase().starts_with(r"PCI\"),
        )),
        _ => None,
    }
}

/// The MAC attribute: see `choose_mac` for the rule. Reads each adapter's
/// permanent (burned-in) address, not the one in use, so Windows' "random
/// hardware addresses" setting and a manual override do not change it.
fn collect_mac_address() -> String {
    let physical = physical_adapters();
    if physical.is_empty() {
        return String::new();
    }

    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64> = Vec::new();
    let mut filled = false;
    while size != 0 && size <= 16 * 1024 * 1024 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `size` bytes and is 8-byte aligned.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if status == ERROR_SUCCESS {
            filled = true;
            break;
        }
        if status != ERROR_BUFFER_OVERFLOW {
            return String::new();
        }
    }
    if !filled {
        return String::new();
    }

    let mut candidates: Vec<(String, bool)> = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        // SAFETY: `adapter` points into `buf`, which GetAdaptersAddresses
        // filled with a linked list whose `Next` pointers stay inside it.
        let a = unsafe { &*adapter };
        adapter = a.Next;

        if a.IfType != IF_TYPE_ETHERNET_CSMACD && a.IfType != IF_TYPE_IEEE80211 {
            continue;
        }
        if a.AdapterName.is_null() {
            continue;
        }
        // SAFETY: AdapterName is a NUL-terminated ANSI string inside `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char) }
            .to_string_lossy()
            .to_uppercase();
        let Some(&(_, built_in)) = physical.iter().find(|(guid, _)| *guid == name) else {
            continue;
        };
        // SAFETY: MIB_IF_ROW2 is plain data, valid when zeroed; the call
        // fills it for the interface named by InterfaceLuid.
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceLuid = a.Luid;
        if unsafe { GetIfEntry2Ex(MibIfEntryNormalWithoutStatistics, &mut row) } != ERROR_SUCCESS {
            continue;
        }
        if row.PhysicalAddressLength != 6 {
            continue;
        }
        let mac = &row.PermanentPhysicalAddress[..6];
        if mac.iter().all(|&b| b == 0) {
            continue;
        }
        candidates.push((format_mac(mac), built_in));
    }
    choose_mac(&candidates)
}

/// Pick the MAC attribute from `(mac, built_in)` candidates: the lowest
/// address among the built-in adapters, or, if there is none, the lowest
/// among the rest.
///
/// Built-in adapters are preferred so that plugging in a dock or a USB
/// Ethernet adapter does not change the result. Taking the lowest, not the
/// first, keeps it independent of the order Windows lists adapters in.
fn choose_mac(candidates: &[(String, bool)]) -> String {
    let lowest = |built_in: bool| {
        candidates
            .iter()
            .filter(|(_, b)| *b == built_in)
            .map(|(mac, _)| mac.clone())
            .min()
    };
    lowest(true).or_else(|| lowest(false)).unwrap_or_default()
}

/// Render `aa:bb:cc:dd:ee:ff`, the form the other platforms use.
fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Values are deliberately not printed: they identify the machine, and
    // test output ends up in CI logs.

    #[test]
    fn test_collect_windows_has_registry_attributes() {
        let attrs = collect_machine_attributes_windows().expect("collect");
        // MachineGuid and the CPU brand come from the registry on every
        // Windows install, virtual machines included. Disk serial and MAC
        // can be absent in a VM.
        assert!(!attrs.machine_id.is_empty(), "MachineGuid was not collected");
        assert!(!attrs.cpu.is_empty(), "CPU brand string was not collected");
        assert!(
            attrs.attribute_count() >= 3,
            "only {} attributes collected",
            attrs.attribute_count()
        );
    }

    #[test]
    fn test_collect_windows_deterministic() {
        let a = collect_machine_attributes_windows().expect("collect");
        let b = collect_machine_attributes_windows().expect("collect");
        assert_eq!(
            compute_machine_fingerprint(&a),
            compute_machine_fingerprint(&b)
        );
    }

    #[test]
    fn test_collect_windows_formats() {
        let attrs = collect_machine_attributes_windows().expect("collect");
        if !attrs.machine_id.is_empty() {
            let parts: Vec<&str> = attrs.machine_id.split('-').collect();
            let lens: Vec<usize> = parts.iter().map(|p| p.len()).collect();
            assert_eq!(lens, vec![8, 4, 4, 4, 12], "MachineGuid is not in GUID form");
            assert!(attrs
                .machine_id
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-'));
        }
        if !attrs.mac_address.is_empty() {
            assert_eq!(attrs.mac_address.len(), 17);
            assert!(attrs
                .mac_address
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f' | ':')));
        }
    }

    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff]),
            "00:1a:2b:3c:4d:ff"
        );
    }

    #[test]
    fn test_query_disk_serial_missing_device_is_empty() {
        assert!(query_disk_serial(r"\\.\PhysicalDrive999").is_empty());
    }

    /// A STORAGE_DEVICE_DESCRIPTOR of `size` bytes whose SerialNumberOffset
    /// field holds `offset`, with `tail` copied in at that offset.
    fn descriptor(size: usize, offset: u32, tail: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; size];
        if size >= SERIAL_NUMBER_OFFSET_FIELD + 4 {
            d[SERIAL_NUMBER_OFFSET_FIELD..SERIAL_NUMBER_OFFSET_FIELD + 4]
                .copy_from_slice(&offset.to_le_bytes());
        }
        let offset = offset as usize;
        if offset < size {
            let n = tail.len().min(size - offset);
            d[offset..offset + n].copy_from_slice(&tail[..n]);
        }
        d
    }

    #[test]
    fn test_parse_disk_serial() {
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("plain", descriptor(64, 40, b"WD-ABC123\0"), "WD-ABC123"),
            ("padded", descriptor(64, 40, b"   S4EWNX0N  \0"), "S4EWNX0N"),
            (
                "nvme eui-64",
                descriptor(64, 40, b"0025_3885_91B1_23A4.\0"),
                "0025_3885_91B1_23A4.",
            ),
            ("no serial (offset 0)", descriptor(64, 0, b""), ""),
            ("offset past the end", descriptor(64, 64, b""), ""),
            ("offset far past the end", descriptor(64, u32::MAX, b""), ""),
            ("not terminated", descriptor(48, 40, b"ABCDEFGH"), ""),
            ("empty string", descriptor(64, 40, b"\0"), ""),
            ("only spaces", descriptor(64, 40, b"    \0"), ""),
            (
                "placeholder zeros",
                descriptor(64, 40, b"0000_0000_0000_0000.\0"),
                "",
            ),
            ("placeholder plain zeros", descriptor(64, 40, b"00000000\0"), ""),
            (
                "too short for the field",
                vec![0u8; SERIAL_NUMBER_OFFSET_FIELD + 3],
                "",
            ),
            ("empty", Vec::new(), ""),
        ];
        for (name, desc, want) in cases {
            assert_eq!(parse_disk_serial(&desc), want, "case: {}", name);
        }
    }

    #[test]
    fn test_choose_mac() {
        let c = |mac: &str, built_in: bool| (mac.to_string(), built_in);
        assert_eq!(choose_mac(&[]), "");
        assert_eq!(choose_mac(&[c("aa:00:00:00:00:02", true)]), "aa:00:00:00:00:02");
        // Lowest built-in, whatever the order.
        assert_eq!(
            choose_mac(&[c("aa:00:00:00:00:09", true), c("aa:00:00:00:00:02", true)]),
            "aa:00:00:00:00:02"
        );
        // A dock with a lower address does not win.
        assert_eq!(
            choose_mac(&[c("aa:00:00:00:00:09", true), c("00:00:00:00:00:01", false)]),
            "aa:00:00:00:00:09"
        );
        // Only removable adapters: the lowest of them.
        assert_eq!(
            choose_mac(&[c("cc:00:00:00:00:05", false), c("bb:00:00:00:00:05", false)]),
            "bb:00:00:00:00:05"
        );
    }
}
