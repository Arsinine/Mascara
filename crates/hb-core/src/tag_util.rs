//! Shared NIP-01 tag accessors used by the typed event parsers (`event`, `binding`).
//! One home for this plumbing so a fix lands in exactly one place.

use nostr::prelude::*;

/// First value of the custom single-named tag `name` (the element after the tag name).
pub(crate) fn tag_val(event: &Event, name: &str) -> Option<String> {
    event
        .tags
        .find(TagKind::custom(name))
        .and_then(|t| t.content())
        .map(str::to_string)
}

/// Read a custom tag as a `u8`, distinguishing *absent* from *malformed* (so callers can
/// report which actually happened, per the M1 review).
pub(crate) fn tag_u8(event: &Event, name: &str) -> TagU8 {
    match tag_val(event, name) {
        None => TagU8::Missing,
        Some(s) => match s.parse::<u8>() {
            Ok(v) => TagU8::Value(v),
            Err(_) => TagU8::Malformed(s),
        },
    }
}

pub(crate) enum TagU8 {
    Value(u8),
    Missing,
    Malformed(String),
}

/// Read a custom tag as a `u64`, distinguishing absent from malformed.
pub(crate) fn tag_u64(event: &Event, name: &str) -> TagU64 {
    match tag_val(event, name) {
        None => TagU64::Missing,
        Some(s) => match s.parse::<u64>() {
            Ok(v) => TagU64::Value(v),
            Err(_) => TagU64::Malformed(s),
        },
    }
}

pub(crate) enum TagU64 {
    Value(u64),
    Missing,
    Malformed(String),
}
