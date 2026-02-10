/// Operations the desktop device can perform independently, without requiring
/// the phone to be present or reachable.
pub fn independent_capabilities() -> Vec<&'static str> {
    vec![
        "profile.view",
        "connection.list",
        "connection.get",
        "feed.list",
        "feed.sync",
        "audit.query",
        "message.list",
        "message.read",
        "agent.list",
        "secrets.catalog",
    ]
}

/// Operations that require the phone to be reachable for delegated approval
/// before the desktop device can execute them.
pub fn phone_required_capabilities() -> Vec<&'static str> {
    vec![
        "secrets.retrieve",
        "secrets.add",
        "secrets.delete",
        "connection.create",
        "connection.revoke",
        "profile.update",
        "personal-data.get",
        "personal-data.update",
        "credential.get",
        "credential.update",
        "pin.setup",
        "pin.unlock",
        "pin.change",
        "service.auth.request",
        "agent.approve",
    ]
}

/// Check whether the given operation can be performed independently (without
/// phone approval).
pub fn is_independent(op: &str) -> bool {
    independent_capabilities().contains(&op)
}

/// Check whether the given operation requires phone approval.
pub fn is_phone_required(op: &str) -> bool {
    phone_required_capabilities().contains(&op)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_independent_capabilities() {
        assert!(is_independent("profile.view"));
        assert!(is_independent("feed.list"));
        assert!(is_independent("secrets.catalog"));
    }

    #[test]
    fn test_phone_required_capabilities() {
        assert!(is_phone_required("secrets.retrieve"));
        assert!(is_phone_required("pin.setup"));
        assert!(is_phone_required("agent.approve"));
    }

    #[test]
    fn test_unknown_capability() {
        assert!(!is_independent("unknown.op"));
        assert!(!is_phone_required("unknown.op"));
    }

    #[test]
    fn test_no_overlap() {
        let independent = independent_capabilities();
        let phone_req = phone_required_capabilities();
        for cap in &independent {
            assert!(
                !phone_req.contains(cap),
                "capability '{}' should not appear in both lists",
                cap,
            );
        }
    }
}
