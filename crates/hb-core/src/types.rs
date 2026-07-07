use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// A single social / contact link the user chooses to display publicly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SocialLink {
    /// Lowercase platform identifier, e.g. "reddit", "discord", "matrix".
    pub platform: String,
    /// The user's handle or URL on that platform.
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Self-reported year the user started hoarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u16>,
    /// Freeform string, e.g. "~12TB". Not validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub est_size: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    /// Freeform contact hint (legacy field, prefer email / social_links).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_hint: Option<String>,
    /// Publicly visible email address — user opts in by setting this field.
    // Approved extension: not in base spec
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// City or region the user is based in, e.g. "Tokyo" or "EU/Germany".
    // Approved extension: not in base spec
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Optional social/contact links (Reddit, Discord, Matrix, etc.).
    /// Always serialized — even when empty — so the frontend reliably gets
    /// an array instead of `undefined`.
    // Approved extension: not in base spec
    #[serde(default)]
    pub social_links: Vec<SocialLink>,
    /// Freeform flags for what the user is willing to do: "trade", "seed", "upload", etc.
    #[serde(default)]
    pub willing_to: Vec<String>,
    /// Computed as union of all published collections; never edited directly.
    #[serde(default)]
    pub content_types: Vec<String>,
    pub updated: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// One shared root directory — a user may publish multiple collections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    /// URL-safe slug derived from `path_alias` at creation time.
    /// Used as the stable key in the relay (`pubkey + slug`).
    pub slug: String,
    /// Human-readable display name shown to visitors.
    pub path_alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub item_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub est_size: Option<String>,
    /// Content type categories for this collection. Renamed from `content_type` (v0.1.x alias kept for backward compat).
    #[serde(default, alias = "content_type")]
    pub content_types: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub last_updated: DateTime<Utc>,
    pub listing: Vec<DirectoryItem>,
}

impl Collection {
    /// Derive a URL-safe slug from a display name.
    /// "Criterion Collection" → "criterion-collection"
    pub fn slug_from_alias(alias: &str) -> String {
        alias
            .to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }
}

// ---------------------------------------------------------------------------
// DirectoryItem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryItem {
    pub name: String,
    // Previously serialized as "type" with lowercase variants.
    // Now serializes as "item_type" with PascalCase variants (matching TS types).
    // #[serde(alias = "type")] accepts old stored data transparently.
    #[serde(alias = "type")]
    pub item_type: ItemType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year: Option<u16>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default)]
    pub children: Vec<DirectoryItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ItemType {
    // Accept old lowercase values from existing stored data.
    #[serde(alias = "folder")]
    Folder,
    #[serde(alias = "file")]
    File,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_derivation() {
        assert_eq!(Collection::slug_from_alias("Criterion Collection"), "criterion-collection");
        assert_eq!(Collection::slug_from_alias("90s Anime!!"), "90s-anime");
        assert_eq!(Collection::slug_from_alias("VHS / Rips"), "vhs-rips");
        assert_eq!(Collection::slug_from_alias("  spaces  "), "spaces");
    }

    #[test]
    fn profile_legacy_json_without_social_links_deserializes() {
        // A profile saved by an older Hoardbook version (v0.1.x) had no
        // `social_links` field. The new app must still load it without error.
        let legacy_json = r#"{
            "display_name": "Gundam",
            "tags": [],
            "languages": [],
            "updated": "2026-04-01T00:00:00Z"
        }"#;
        let parsed: Profile =
            serde_json::from_str(legacy_json).expect("legacy profile must deserialize");
        assert_eq!(parsed.display_name, "Gundam");
        assert!(parsed.social_links.is_empty());
    }

    #[test]
    fn profile_empty_social_links_round_trips_as_array() {
        // Bug: when `social_links` was tagged `skip_serializing_if = "Vec::is_empty"`,
        // an empty vec was OMITTED from the JSON sent over Tauri IPC. The frontend
        // then saw `social_links: undefined` and crashed on `form.social_links.find()`,
        // leaving the main panel blank after launch.
        //
        // The contract for any Vec field exposed to the frontend: serialize as `[]`
        // when empty, never omit. Option fields may still skip-serialize because
        // `?.` handles undefined cleanly on the JS side.
        let profile = Profile {
            display_name: "Gundam".into(),
            bio: None,
            tags: vec![],
            since: None,
            est_size: None,
            languages: vec![],
            contact_hint: None,
            email: None,
            location: None,
            social_links: vec![],
            willing_to: vec![],
            content_types: vec![],
            updated: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(
            json.contains("\"social_links\":[]"),
            "social_links must appear as [] in JSON, got: {json}"
        );
    }

    #[test]
    fn directory_item_serde_roundtrip() {
        let item = DirectoryItem {
            name: "Seven Samurai (1954)".into(),
            item_type: ItemType::File,
            size: Some("14.2GB".into()),
            format: Some("MKV".into()),
            year: Some(1954),
            tags: vec!["kurosawa".into()],
            note: None,
            children: vec![],
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: DirectoryItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, item.name);
        assert_eq!(back.item_type, ItemType::File);
        assert_eq!(back.size.as_deref(), Some("14.2GB"));
        assert_eq!(back.year, Some(1954));
        assert_eq!(back.tags, ["kurosawa"]);
        assert!(back.children.is_empty());
        // note: None must be absent from JSON, not serialized as null
        assert!(!json.contains("\"note\""), "absent note field must not appear in JSON");
    }

    #[test]
    fn directory_item_no_hash_in_json() {
        let item = DirectoryItem {
            name: "film.mkv".into(),
            item_type: ItemType::File,
            size: Some("14.2GB".into()),
            format: Some("MKV".into()),
            year: None,
            tags: vec![],
            note: None,
            children: vec![],
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(
            !json.contains("sha256"),
            "DirectoryItem must not expose sha256 in serialized form, got: {json}"
        );
    }

    #[test]
    fn collection_no_internal_fields() {
        let col = Collection {
            slug: "films".into(),
            path_alias: "Films".into(),
            description: None,
            item_count: 0,
            est_size: None,
            content_types: vec![],
            tags: vec![],
            languages: vec![],
            last_updated: chrono::Utc::now(),
            listing: vec![],
        };
        let json = serde_json::to_string(&col).unwrap();
        assert!(
            !json.contains("total_bytes"),
            "Collection must not expose total_bytes in serialized form"
        );
        assert!(
            !json.contains("\"sorted\""),
            "Collection must not expose sorted in serialized form"
        );
    }

    #[test]
    fn content_types_union_sorted_deduped() {
        // Validate that content_types union logic produces a sorted, deduplicated
        // list — the same logic used in publish_collection.
        let type_sets: Vec<Vec<String>> = vec![
            vec!["video".into(), "audio".into()],
            vec!["audio".into(), "image".into()],
            vec!["video".into()],
        ];
        let mut aggregate: Vec<String> = type_sets.into_iter().flatten().collect();
        aggregate.sort();
        aggregate.dedup();
        assert_eq!(aggregate, vec!["audio", "image", "video"]);
    }
}
