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
//! install, so treat the rules in this file as a wire format. They follow
//! the agent connector's Windows collector as proposed in vettid-agent#6
//! (closed, not merged), except that the disk serial falls back to
//! `PhysicalDrive0` only when the Windows drive is unknown (see
//! `collect_disk_serial`).
//!
//! Requires Windows 10 version 1703 or later (`GetIfEntry2Ex`).

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE,
    INVALID_HANDLE_VALUE,
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
    compute_machine_bound_key, compute_machine_fingerprint, compute_storage_binding, compute_machine_fingerprint_hex,
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

/// Serial number of the disk that holds the Windows volume. The volume is
/// opened with no access rights, which is enough for the query and works
/// for a standard user.
///
/// `PhysicalDrive0` is asked only when the Windows drive itself is unknown.
/// When the Windows volume answers with no serial, the result is empty:
/// physical drive numbers move when a dock, USB disk or second internal
/// disk is attached, and a different disk's serial would change the key.
///
/// The string is whatever the storage driver reports. The inbox NVMe driver
/// gives the drive's EUI-64, not the serial printed on the label, and a
/// vendor driver may give a different string for the same drive.
fn collect_disk_serial() -> String {
    query_disk_serial(&disk_serial_device(system_drive()))
}

/// The device to ask for the disk serial: the Windows volume, or the first
/// physical disk when the Windows drive is unknown.
fn disk_serial_device(system_drive: Option<String>) -> String {
    match system_drive {
        Some(drive) => format!(r"\\.\{}", drive),
        None => r"\\.\PhysicalDrive0".to_string(),
    }
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

    let serial = storage_device_descriptor(handle)
        .map(|descriptor| parse_disk_serial(&descriptor))
        .unwrap_or_default();
    // SAFETY: `handle` was returned by CreateFileW and is closed once.
    unsafe { CloseHandle(handle) };
    serial
}

/// Length of STORAGE_DESCRIPTOR_HEADER (Version, Size).
const DESCRIPTOR_HEADER_LEN: usize = 8;
/// Upper bound on the descriptor size a driver may ask for.
const MAX_DESCRIPTOR_LEN: usize = 64 * 1024;

/// The whole STORAGE_DEVICE_DESCRIPTOR: first the header, which gives the
/// size the descriptor needs, then the descriptor in a buffer of that size.
/// A fixed buffer would fail for a drive with large raw properties.
fn storage_device_descriptor(handle: HANDLE) -> Option<Vec<u8>> {
    let mut header = [0u8; DESCRIPTOR_HEADER_LEN];
    if storage_property_query(handle, &mut header)? < DESCRIPTOR_HEADER_LEN {
        return None;
    }
    let size = descriptor_size(&header)?;
    let mut descriptor = vec![0u8; size];
    let returned = storage_property_query(handle, &mut descriptor)?;
    descriptor.truncate(returned);
    Some(descriptor)
}

/// The `Size` a STORAGE_DESCRIPTOR_HEADER reports, if it is plausible.
fn descriptor_size(header: &[u8; DESCRIPTOR_HEADER_LEN]) -> Option<usize> {
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    (DESCRIPTOR_HEADER_LEN..=MAX_DESCRIPTOR_LEN).contains(&size).then_some(size)
}

/// IOCTL_STORAGE_QUERY_PROPERTY for the device descriptor into `out`.
/// Returns the number of bytes written.
fn storage_property_query(handle: HANDLE, out: &mut [u8]) -> Option<usize> {
    let query = StoragePropertyQuery {
        property_id: 0,
        query_type: 0,
        additional_parameters: [0],
    };
    let mut returned: u32 = 0;
    // SAFETY: input and output pointers are live buffers of the stated
    // sizes; the caller keeps the handle open for the call.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const StoragePropertyQuery as *const c_void,
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            out.as_mut_ptr() as *mut c_void,
            out.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    let returned = returned as usize;
    (ok != 0 && returned <= out.len()).then_some(returned)
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
        if status == ERROR_MORE_DATA {
            // A subkey name longer than the buffer is not an adapter
            // ("0000", "0001", ...). Skip it, do not stop.
            continue;
        }
        if status != ERROR_SUCCESS {
            // ERROR_NO_MORE_ITEMS.
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
/// in an internal slot, as opposed to a USB adapter. (A Thunderbolt or USB4
/// dock also appears on the PCI bus.)
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

    classify_adapter(characteristics, &guid, &instance)
}

/// The adapter rule, from an adapter's registry values: `Some((guid,
/// built_in))` for a physical adapter (NCF_PHYSICAL set and an instance
/// GUID present), with the GUID upper-cased and built in meaning a
/// `PCI\` device instance; `None` for anything else.
fn classify_adapter(
    characteristics: Option<u32>,
    guid: &str,
    instance: &str,
) -> Option<(String, bool)> {
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
    // The needed size can grow between calls if an adapter appears.
    for _ in 0..4 {
        if size == 0 || size > 16 * 1024 * 1024 {
            break;
        }
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
        if let Some(mac) = usable_mac(row.PhysicalAddressLength, &row.PermanentPhysicalAddress) {
            candidates.push((mac, built_in));
        }
    }
    choose_mac(&candidates)
}

/// The permanent address as `aa:bb:cc:dd:ee:ff`, if it is a usable
/// 6-byte address: not another length, and not all zeros.
fn usable_mac(length: u32, permanent: &[u8]) -> Option<String> {
    if length != 6 || permanent.len() < 6 {
        return None;
    }
    let mac = &permanent[..6];
    if mac.iter().all(|&b| b == 0) {
        return None;
    }
    Some(format_mac(mac))
}

/// Pick the MAC attribute from `(mac, built_in)` candidates: the lowest
/// address among the built-in adapters, or, if there is none, the lowest
/// among the rest.
///
/// Built-in adapters are preferred so that plugging in a USB Ethernet
/// adapter or a USB dock does not change the result. Taking the lowest, not
/// the first, keeps it independent of the order Windows lists adapters in.
///
/// Known limits: a Thunderbolt or USB4 dock tunnels PCIe, so its adapter
/// also counts as built in; and an adapter disabled in Windows is not
/// listed at all. Either can change the result.
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
    fn test_disk_serial_device() {
        assert_eq!(disk_serial_device(Some("C:".to_string())), r"\\.\C:");
        assert_eq!(disk_serial_device(Some("D:".to_string())), r"\\.\D:");
        // PhysicalDrive0 only when the Windows drive is unknown.
        assert_eq!(disk_serial_device(None), r"\\.\PhysicalDrive0");
    }

    #[test]
    fn test_descriptor_size() {
        let header = |size: u32| {
            let mut h = [0u8; DESCRIPTOR_HEADER_LEN];
            h[4..8].copy_from_slice(&size.to_le_bytes());
            h
        };
        assert_eq!(descriptor_size(&header(1024)), Some(1024));
        assert_eq!(descriptor_size(&header(8)), Some(8));
        assert_eq!(descriptor_size(&header(64 * 1024)), Some(64 * 1024));
        assert_eq!(descriptor_size(&header(7)), None);
        assert_eq!(descriptor_size(&header(0)), None);
        assert_eq!(descriptor_size(&header(64 * 1024 + 1)), None);
        assert_eq!(descriptor_size(&header(u32::MAX)), None);
    }

    #[test]
    fn test_classify_adapter() {
        let guid = "{1a2b3c4d-0000-1111-2222-333344445555}";
        let upper = "{1A2B3C4D-0000-1111-2222-333344445555}";
        // Physical, on the PCI bus: built in.
        assert_eq!(
            classify_adapter(Some(NCF_PHYSICAL), guid, r"PCI\VEN_8086&DEV_15F3\3&11583659&0&FE"),
            Some((upper.to_string(), true))
        );
        // Other flags alongside NCF_PHYSICAL; lower-case instance prefix.
        assert_eq!(
            classify_adapter(Some(NCF_PHYSICAL | 0x80), guid, r"pci\ven_10ec&dev_8168\01"),
            Some((upper.to_string(), true))
        );
        // Physical, on USB: not built in.
        assert_eq!(
            classify_adapter(Some(NCF_PHYSICAL), guid, r"USB\VID_0BDA&PID_8153\000001"),
            Some((upper.to_string(), false))
        );
        // No device instance: physical, not built in.
        assert_eq!(classify_adapter(Some(NCF_PHYSICAL), guid, ""), Some((upper.to_string(), false)));
        // Virtual (no NCF_PHYSICAL), no Characteristics, or no GUID: none.
        assert_eq!(classify_adapter(Some(0x1), guid, r"ROOT\VMS_MP\0000"), None);
        assert_eq!(classify_adapter(Some(0), guid, r"PCI\VEN_8086"), None);
        assert_eq!(classify_adapter(None, guid, r"PCI\VEN_8086"), None);
        assert_eq!(classify_adapter(Some(NCF_PHYSICAL), "", r"PCI\VEN_8086"), None);
    }

    #[test]
    fn test_usable_mac() {
        let mut addr = [0u8; 32];
        addr[..6].copy_from_slice(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff]);
        assert_eq!(usable_mac(6, &addr).as_deref(), Some("00:1a:2b:3c:4d:ff"));
        // Not a 6-byte address.
        assert_eq!(usable_mac(0, &addr), None);
        assert_eq!(usable_mac(8, &addr), None);
        // All zeros.
        assert_eq!(usable_mac(6, &[0u8; 32]), None);
        // Shorter than 6 bytes available.
        assert_eq!(usable_mac(6, &addr[..5]), None);
        // Only the first 6 bytes count.
        let mut trailing = addr;
        trailing[6] = 0xee;
        assert_eq!(usable_mac(6, &trailing).as_deref(), Some("00:1a:2b:3c:4d:ff"));
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
