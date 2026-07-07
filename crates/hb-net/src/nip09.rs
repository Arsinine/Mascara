//! NIP-09 event deletion — the unpublish lever (spec §Collection Manager → Unpublish).
//!
//! Deletion is **best-effort**: a compliant relay drops the referenced event, but a relay may
//! ignore the request. So this module's contract is only that the *request* is well-formed and
//! signed by the same identity that authored the target — whether any given relay honours it is
//! asserted at the L2 layer (N5), not here.

use hb_core::Identity;
use nostr::nips::nip09::EventDeletionRequest;
use nostr::prelude::*;

use crate::error::NetError;

/// Build a signed NIP-09 deletion request (kind 5) referencing `target` by event id.
pub fn build_deletion(identity: &Identity, target: &Event) -> Result<Event, NetError> {
    let req = EventDeletionRequest::new().id(target.id);
    Ok(identity.sign(EventBuilder::delete(req))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hb_core::event::{build_teaser, Teaser};

    #[test]
    fn deletion_request_is_well_formed() {
        let id = Identity::generate();
        let teaser = build_teaser(
            &id,
            &Teaser {
                display_name: "x".into(),
                bio: String::new(),
                tags: vec![],
                content_types: vec![],
            },
        )
        .unwrap();

        let del = build_deletion(&id, &teaser).unwrap();
        assert_eq!(del.kind, Kind::EventDeletion);
        assert_eq!(del.pubkey, id.public_key());
        assert!(del.verify().is_ok(), "deletion request must be a valid signed event");
        // It must reference exactly the target event id via an `e` tag.
        let target_hex = teaser.id.to_hex();
        assert!(
            del.tags.iter().any(|t| t.content() == Some(target_hex.as_str())),
            "deletion must reference the target event id"
        );
    }
}
