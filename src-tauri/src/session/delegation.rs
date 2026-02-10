use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Pending approval tracking
// ---------------------------------------------------------------------------

/// Represents a single pending phone-approval request.
#[derive(Debug)]
pub struct PendingApproval {
    /// Unique identifier for this approval request.
    pub request_id: String,
    /// The operation being requested (e.g., "secrets.retrieve").
    pub operation: String,
    /// When this pending approval was created.
    pub created_at: Instant,
}

// ---------------------------------------------------------------------------
// Delegation manager
// ---------------------------------------------------------------------------

/// Tracks pending delegated-approval requests that have been sent to the
/// phone and are awaiting a response.
pub struct DelegationManager {
    pending: HashMap<String, PendingApproval>,
}

impl DelegationManager {
    /// Create a new, empty delegation manager.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Record a new pending approval request.
    pub fn add_pending(&mut self, request_id: String, operation: String) {
        let approval = PendingApproval {
            request_id: request_id.clone(),
            operation,
            created_at: Instant::now(),
        };
        self.pending.insert(request_id, approval);
    }

    /// Resolve (remove and return) a pending approval by its request ID.
    ///
    /// Returns `None` if no such pending request exists.
    pub fn resolve(&mut self, request_id: &str) -> Option<PendingApproval> {
        self.pending.remove(request_id)
    }

    /// Remove all pending approvals that are older than `max_age`.
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.pending.retain(|_, approval| {
            now.duration_since(approval.created_at) < max_age
        });
    }

    /// Return the number of currently pending approvals.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check whether a specific request is still pending.
    pub fn is_pending(&self, request_id: &str) -> bool {
        self.pending.contains_key(request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_resolve() {
        let mut mgr = DelegationManager::new();
        mgr.add_pending("req-001".to_string(), "secrets.retrieve".to_string());
        assert_eq!(mgr.pending_count(), 1);
        assert!(mgr.is_pending("req-001"));

        let resolved = mgr.resolve("req-001");
        assert!(resolved.is_some());
        let resolved = resolved.unwrap();
        assert_eq!(resolved.request_id, "req-001");
        assert_eq!(resolved.operation, "secrets.retrieve");
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_resolve_nonexistent() {
        let mut mgr = DelegationManager::new();
        assert!(mgr.resolve("nope").is_none());
    }

    #[test]
    fn test_cleanup_stale() {
        let mut mgr = DelegationManager::new();
        mgr.add_pending("req-001".to_string(), "secrets.retrieve".to_string());
        mgr.add_pending("req-002".to_string(), "pin.setup".to_string());

        // Nothing should be removed with a generous max_age.
        mgr.cleanup_stale(Duration::from_secs(3600));
        assert_eq!(mgr.pending_count(), 2);

        // With a zero max_age, everything is stale.
        mgr.cleanup_stale(Duration::from_secs(0));
        assert_eq!(mgr.pending_count(), 0);
    }
}
