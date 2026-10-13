//! Windows-specific machine fingerprinting for platform binding.
//!
//! Collects the same five machine attributes as Linux and macOS (hostname,
//! machine id, CPU brand, disk serial, MAC address) and uses the same
//! MachineAttributes/fingerprint types.
//!
//! SECURITY: every attribute is read through the registry or a Win32 call.
//! Nothing is executed, so there is no helper binary (`ioreg`, `lsblk`) that
//! a planted program earlier on PATH could impersonate.

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ENUMERATE_SUB_KEYS, KEY_WOW64_64KEY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    RRF_SUBKEY_WOW6464KEY,
};
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
/// - disk_serial: serial number of the disk under the system volume
/// - mac_address: lowest MAC among the adapters Windows marks as physical
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

/// Serial number of the disk that holds the system volume, falling back to
/// the first physical disk. Both are opened with no access rights, which is
/// enough for the query and works for a standard user.
fn collect_disk_serial() -> String {
    let mut candidates = Vec::new();
    if let Ok(drive) = std::env::var("SystemDrive") {
        let b = drive.as_bytes();
        if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            candidates.push(format!(r"\\.\{}", drive));
        }
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

    let returned = (returned as usize).min(buf.len());
    if ok == 0 || returned < SERIAL_NUMBER_OFFSET_FIELD + 4 {
        return String::new();
    }
    let data = &buf[..returned];
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
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |n| offset + n);
    String::from_utf8_lossy(&data[offset..end]).trim().to_string()
}

const NET_ADAPTER_CLASS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
/// NCF_PHYSICAL: the adapter is a physical device, not a virtual one.
const NCF_PHYSICAL: u32 = 0x4;
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_IEEE80211: u32 = 71;
const AF_UNSPEC: u32 = 0;

/// Instance GUIDs (upper case, with braces) of the network adapters Windows
/// marks as physical. Virtual switches, VPN adapters and the WSL and Hyper-V
/// adapters are not marked, and they come and go, which would change the
/// fingerprint.
fn physical_adapter_guids() -> Vec<String> {
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
        if let Some(guid) = physical_adapter_guid_at(&path) {
            guids.push(guid);
        }
    }
    // SAFETY: `class_key` was opened above and is closed once.
    unsafe { RegCloseKey(class_key) };
    guids
}

/// The adapter's instance GUID if `path` describes a physical adapter.
fn physical_adapter_guid_at(path: &str) -> Option<String> {
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
    // SAFETY: `key` was opened above and is closed once.
    unsafe { RegCloseKey(key) };

    match characteristics {
        Some(c) if c & NCF_PHYSICAL != 0 && !guid.is_empty() => Some(guid.to_uppercase()),
        _ => None,
    }
}

/// Lowest MAC address among the physical Ethernet and Wi-Fi adapters,
/// whether or not they are connected. Taking the lowest, not the first,
/// keeps the result independent of the order Windows lists adapters in.
fn collect_mac_address() -> String {
    let physical = physical_adapter_guids();
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
    for _ in 0..3 {
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

    let mut macs: Vec<String> = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        // SAFETY: `adapter` points into `buf`, which GetAdaptersAddresses
        // filled with a linked list whose `Next` pointers stay inside it.
        let a = unsafe { &*adapter };
        adapter = a.Next;

        if a.IfType != IF_TYPE_ETHERNET_CSMACD && a.IfType != IF_TYPE_IEEE80211 {
            continue;
        }
        if a.PhysicalAddressLength != 6 || a.AdapterName.is_null() {
            continue;
        }
        // SAFETY: AdapterName is a NUL-terminated ANSI string inside `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char) }
            .to_string_lossy()
            .to_uppercase();
        if !physical.contains(&name) {
            continue;
        }
        let mac = &a.PhysicalAddress[..6];
        if mac.iter().all(|&b| b == 0) {
            continue;
        }
        macs.push(format_mac(mac));
    }
    macs.sort();
    macs.into_iter().next().unwrap_or_default()
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
}
