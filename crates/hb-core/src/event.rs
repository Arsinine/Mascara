//! Typed Hoardbook events on NIP-01: the **public teaser** and the **encrypted collection
//! listing** (the presence/binding event lives in `binding`). Each carries a signed schema
//! version, and each parser refuses an unknown version rather than trusting the event.

use nostr::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::HbError;
use crate::identity::{verify_event, Identity};
use crate::listing::{decrypt_listing, encrypt_listing, BrowseKey};
use crate::tag_util::{tag_u8, tag_val, TagU8};
use crate::version::{check_schema, CRYPTO_V, SCHEMA_V};

/// Public teaser kind — parameterized-replaceable (30xxx).
pub const KIND_TEASER: u16 = 30_117;
/// Collection-listing kind — parameterized-replaceable (30xxx), `d` = slug.
pub const KIND_LISTING: u16 = 31_111;

const TAG_SCHEMA: &str = "hb-v";
const TAG_CRYPTO: &str = "hb-cv";
const TEASER_D: &str = "hoardbook-teaser";

/// The public teaser — pseudonymous profile fields. There is **no `contact_hint`**: that
/// field re-links the `npub` to a real handle, so it is encrypted and share-code-gated,
/// never placed in this public event (spec §The Profile).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Teaser {
    pub display_name: String,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub content_types: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Versioned<T> {
    v: u8,
    #[serde(flatten)]
    inner: T,
}

/// Build a signed public teaser. `tags` + `content_types` are also emitted as `t` tags so
/// the teaser is discoverable by tag search without exposing any listing.
pub fn build_teaser(identity: &Identity, teaser: &Teaser) -> Result<Event, HbError> {
    let content = serde_json::to_string(&Versioned { v: SCHEMA_V, inner: teaser.clone() })?;
    let mut tags = vec![
        Tag::identifier(TEASER_D),
        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
    ];
    for t in teaser.tags.iter().chain(teaser.content_types.iter()) {
        tags.push(Tag::hashtag(t));
    }
    identity.sign(EventBuilder::new(Kind::from_u16(KIND_TEASER), content).tags(tags))
}

/// Verify + parse a teaser. Rejects the wrong kind and a missing/unknown schema version.
pub fn parse_teaser(event: &Event) -> Result<Teaser, HbError> {
    verify_event(event)?;
    if event.kind != Kind::from_u16(KIND_TEASER) {
        return Err(HbError::InvalidEvent(format!(
            "expected teaser kind {KIND_TEASER}, got {}",
            event.kind.as_u16()
        )));
    }
    let payload: Versioned<Teaser> = serde_json::from_str(&event.content)?;
    check_schema(payload.v)?;
    Ok(payload.inner)
}

/// Build a signed, encrypted collection-listing event (kind 31111, `d` = slug).
pub fn build_listing_event(
    identity: &Identity,
    slug: &str,
    browse_key: &BrowseKey,
    listing_json: &str,
) -> Result<Event, HbError> {
    let content = encrypt_listing(browse_key, listing_json)?;
    identity.sign(EventBuilder::new(Kind::from_u16(KIND_LISTING), content).tags([
        Tag::identifier(slug),
        Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
        Tag::custom(TagKind::custom(TAG_CRYPTO), [CRYPTO_V.to_string()]),
    ]))
}

/// Verify + parse a listing event and decrypt it with the browse-key. Returns `(slug, json)`.
pub fn parse_listing_event(
    event: &Event,
    browse_key: &BrowseKey,
) -> Result<(String, String), HbError> {
    verify_event(event)?;
    if event.kind != Kind::from_u16(KIND_LISTING) {
        return Err(HbError::InvalidEvent("expected listing kind".into()));
    }
    let slug = event
        .tags
        .identifier()
        .ok_or_else(|| HbError::InvalidEvent("listing event missing d=slug".into()))?
        .to_string();
    // Schema version: the content is ciphertext, so the signed `hb-v` tag is authoritative —
    // validate it (a future version is refused, not silently mis-read).
    let schema = tag_val(event, TAG_SCHEMA)
        .and_then(|s| s.parse::<u8>().ok())
        .ok_or_else(|| HbError::InvalidEvent("listing event missing or malformed schema version".into()))?;
    check_schema(schema)?;
    let crypto_v = match tag_u8(event, TAG_CRYPTO) {
        TagU8::Value(v) => v,
        TagU8::Missing => {
            return Err(HbError::InvalidEvent("listing event missing crypto version tag".into()))
        }
        TagU8::Malformed(s) => {
            return Err(HbError::InvalidEvent(format!("listing event malformed crypto version: {s}")))
        }
    };
    let json = decrypt_listing(browse_key, crypto_v, &event.content)?;
    Ok((slug, json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::KIND_PRESENCE;

    fn teaser() -> Teaser {
        Teaser {
            display_name: "archivebox_prime".into(),
            bio: "90s anime, VHS rips".into(),
            tags: vec!["anime".into(), "vhs".into()],
            content_types: vec!["video".into()],
        }
    }

    #[test]
    fn teaser_roundtrips_and_carries_hashtags() {
        let id = Identity::generate();
        let ev = build_teaser(&id, &teaser()).unwrap();
        assert_eq!(parse_teaser(&ev).unwrap(), teaser());
        // Discovery: tags + content_types surface as `t` tags.
        let hashtags = ev.tags.hashtags().collect::<Vec<_>>();
        assert!(hashtags.contains(&"anime") && hashtags.contains(&"video"));
    }

    #[test]
    fn teaser_omits_contact_hint() {
        // The public teaser event must never carry the deanonymizing contact_hint (N1/AB10).
        let id = Identity::generate();
        let ev = build_teaser(&id, &teaser()).unwrap();
        assert!(!ev.content.contains("contact_hint"));
        // And the struct has no such field to leak through.
        assert!(!serde_json::to_string(&teaser()).unwrap().contains("contact_hint"));
    }

    #[test]
    fn builder_inserts_schema_v() {
        let id = Identity::generate();
        let ev = build_teaser(&id, &teaser()).unwrap();
        assert!(ev.content.contains(&format!("\"v\":{SCHEMA_V}")));
        assert_eq!(tag_val(&ev, TAG_SCHEMA).as_deref(), Some(SCHEMA_V.to_string().as_str()));
    }

    #[test]
    fn parse_rejects_unknown_schema_v() {
        // A teaser whose signed payload claims a future version is recognised and refused.
        let id = Identity::generate();
        let content = serde_json::to_string(&Versioned { v: SCHEMA_V + 1, inner: teaser() }).unwrap();
        let ev = id
            .sign(EventBuilder::new(Kind::from_u16(KIND_TEASER), content).tag(Tag::identifier(TEASER_D)))
            .unwrap();
        assert!(matches!(parse_teaser(&ev), Err(HbError::UnsupportedVersion(v)) if v == SCHEMA_V + 1));
    }

    #[test]
    fn parse_rejects_missing_v() {
        // Content with no `v` field is rejected, not parsed as v1.
        let id = Identity::generate();
        let content = serde_json::to_string(&teaser()).unwrap(); // no version wrapper
        let ev = id
            .sign(EventBuilder::new(Kind::from_u16(KIND_TEASER), content).tag(Tag::identifier(TEASER_D)))
            .unwrap();
        assert!(parse_teaser(&ev).is_err());
    }

    #[test]
    fn parse_rejects_wrong_kind() {
        // A listing event handed to the teaser parser is rejected on kind.
        let id = Identity::generate();
        let bk: BrowseKey = rand::random();
        let listing = build_listing_event(&id, "criterion", &bk, "{}").unwrap();
        assert!(matches!(parse_teaser(&listing), Err(HbError::InvalidEvent(_))));
    }

    #[test]
    fn listing_event_carries_d_slug_and_base64_body() {
        let id = Identity::generate();
        let bk: BrowseKey = rand::random();
        let json = r#"{"slug":"criterion","items":[{"name":"Ran"}]}"#;
        let ev = build_listing_event(&id, "criterion", &bk, json).unwrap();
        assert_eq!(ev.tags.identifier(), Some("criterion"));
        let (slug, decrypted) = parse_listing_event(&ev, &bk).unwrap();
        assert_eq!(slug, "criterion");
        assert_eq!(decrypted, json);
    }

    #[test]
    fn listing_wrong_browse_key_fails() {
        let id = Identity::generate();
        let bk: BrowseKey = rand::random();
        let other: BrowseKey = rand::random();
        let ev = build_listing_event(&id, "x", &bk, "{}").unwrap();
        assert!(parse_listing_event(&ev, &other).is_err());
    }

    #[test]
    fn listing_rejects_unknown_schema_v() {
        // A listing event whose signed hb-v tag claims a future version is refused on parse,
        // not silently accepted (the forward-compat contract the other parsers uphold).
        let id = Identity::generate();
        let bk: BrowseKey = rand::random();
        let content = encrypt_listing(&bk, "{}").unwrap();
        let ev = id
            .sign(EventBuilder::new(Kind::from_u16(KIND_LISTING), content).tags([
                Tag::identifier("x"),
                Tag::custom(TagKind::custom(TAG_SCHEMA), [(SCHEMA_V + 1).to_string()]),
                Tag::custom(TagKind::custom(TAG_CRYPTO), [CRYPTO_V.to_string()]),
            ]))
            .unwrap();
        assert!(matches!(
            parse_listing_event(&ev, &bk),
            Err(HbError::UnsupportedVersion(v)) if v == SCHEMA_V + 1
        ));
    }

    #[test]
    fn listing_malformed_crypto_version_distinguished() {
        let id = Identity::generate();
        let bk: BrowseKey = rand::random();
        let content = encrypt_listing(&bk, "{}").unwrap();
        let ev = id
            .sign(EventBuilder::new(Kind::from_u16(KIND_LISTING), content).tags([
                Tag::identifier("x"),
                Tag::custom(TagKind::custom(TAG_SCHEMA), [SCHEMA_V.to_string()]),
                Tag::custom(TagKind::custom(TAG_CRYPTO), ["256".to_string()]),
            ]))
            .unwrap();
        match parse_listing_event(&ev, &bk) {
            Err(HbError::InvalidEvent(m)) => assert!(m.contains("malformed"), "got: {m}"),
            other => panic!("expected malformed crypto version, got {other:?}"),
        }
    }

    #[test]
    fn replaceable_kind_ranges_correct() {
        // Presence is replaceable (10000–19999); teaser & listing are addressable (30000–39999).
        assert!((10_000..20_000).contains(&KIND_PRESENCE));
        assert!((30_000..40_000).contains(&KIND_TEASER));
        assert!((30_000..40_000).contains(&KIND_LISTING));
    }
}
