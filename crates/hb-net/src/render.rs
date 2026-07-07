//! The partial-listing **render model** (M3): turn a set of fetched + decrypted listing payloads
//! into a directory tree annotated with **"K of N folders available"** when parts are missing.
//!
//! This is the lenient sibling of [`crate::split::restitch_listing`]. Restitch is all-or-nothing —
//! it *errors* on a missing part because the caller wanted the whole tree. The browse UI instead
//! wants to render whatever arrived and tell the user what's missing (spec §Data Model: "N of M
//! folders available on loss"; AB8 withhold). So `render_listing` treats a **missing** expected
//! part as graceful degradation (reported in `missing`), while a **foreign / duplicate /
//! out-of-range** part — something a hostile relay injected that the index never named — is a hard
//! rejection with a reason (it signals tampering, not loss). An index claiming more than
//! [`MAX_LISTING_PARTS`] is refused before any allocation (a read-side DoS cap the write-side
//! budget can't bound).

use serde_json::{Map, Value};

use crate::error::NetError;

/// Read-side cap on the part count an index may claim. A hostile relay can serve an index
/// asserting an enormous `parts`, so we refuse it before collecting/allocating.
pub const MAX_LISTING_PARTS: usize = 4096;

/// A rendered listing tree, possibly partial.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedListing {
    /// Top-level metadata preserved from the listing (slug, content_types, …) — `entries` removed.
    pub meta: Map<String, Value>,
    /// The folder/file entries from the parts that actually arrived, in index order.
    pub entries: Vec<Value>,
    /// Total parts the index says exist (1 for an unsplit listing).
    pub parts_total: usize,
    /// Parts present (K). `parts_present == parts_total` ⇔ the tree is complete.
    pub parts_present: usize,
    /// Indices of the parts that did not arrive (empty when complete).
    pub missing: Vec<usize>,
}

impl RenderedListing {
    /// Whether every part is present. (The human-facing "K of N folders available" *string* is the
    /// UI's concern — see `ui/src/lib/browse-view.ts::availabilityBadge`; this data struct exposes
    /// the counts, not display text.)
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Render fetched + decrypted listing payloads into a (possibly partial) tree.
///
/// **The caller must pass payloads from signature-verified + decrypted events** (e.g. via
/// `hb_core::event::parse_listing_event`) — like restitch, this trusts the JSON it is given for
/// *provenance* and only validates *shape*.
pub fn render_listing(payloads: &[String]) -> Result<RenderedListing, NetError> {
    if payloads.is_empty() {
        return Err(NetError::Split("no listing payloads to render".into()));
    }

    // Parse all payloads; locate the index (split == true) and the content parts.
    let mut index: Option<Map<String, Value>> = None;
    let mut content: Vec<(usize, usize, Vec<Value>)> = Vec::new();
    let mut plain_single: Option<Map<String, Value>> = None;
    for json in payloads {
        let v: Value = serde_json::from_str(json).map_err(|e| NetError::Split(e.to_string()))?;
        let obj = v.as_object().ok_or_else(|| NetError::Split("part is not an object".into()))?;
        if obj.get("split") == Some(&Value::Bool(true)) {
            index = Some(obj.clone());
        } else if let (Some(p), Some(t)) =
            (obj.get("part").and_then(Value::as_u64), obj.get("parts").and_then(Value::as_u64))
        {
            let entries =
                obj.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
            content.push((p as usize, t as usize, entries));
        } else {
            // No split marker and no part/parts → a whole unsplit listing.
            plain_single = Some(obj.clone());
        }
    }

    // Unsplit single listing: only valid when it's the *only* payload (otherwise we have stray
    // content parts with no index, which is a tampered/incoherent set).
    if let Some(mut obj) = plain_single {
        if payloads.len() != 1 {
            return Err(NetError::Split(
                "content/plain parts present without a split index".into(),
            ));
        }
        let entries = obj.remove("entries").and_then(|v| match v {
            Value::Array(a) => Some(a),
            _ => None,
        });
        return Ok(RenderedListing {
            meta: obj,
            entries: entries.unwrap_or_default(),
            parts_total: 1,
            parts_present: 1,
            missing: Vec::new(),
        });
    }

    let index = index.ok_or_else(|| NetError::Split("no index part found".into()))?;
    let n = index
        .get("parts")
        .and_then(Value::as_u64)
        .ok_or_else(|| NetError::Split("index missing part count".into()))? as usize;
    if n > MAX_LISTING_PARTS {
        return Err(NetError::Split(format!(
            "index claims {n} parts, exceeds the {MAX_LISTING_PARTS}-part cap"
        )));
    }

    // Slot the content parts by index, rejecting anything the index never named.
    let mut slots: Vec<Option<Vec<Value>>> = vec![None; n];
    for (p, total, entries) in content {
        if total != n {
            return Err(NetError::Split(format!("part claims {total} parts, index says {n}")));
        }
        if p >= n {
            return Err(NetError::Split(format!("foreign part {p}: index names only 0..{n}")));
        }
        if slots[p].is_some() {
            return Err(NetError::Split(format!("duplicate part {p}")));
        }
        slots[p] = Some(entries);
    }

    let mut entries = Vec::new();
    let mut missing = Vec::new();
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(chunk) => entries.extend(chunk),
            None => missing.push(i),
        }
    }
    let parts_present = n - missing.len();

    let mut meta = index;
    meta.remove("split");
    meta.remove("parts");
    Ok(RenderedListing { meta, entries, parts_total: n, parts_present, missing })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::split_listing;

    fn listing(n: usize) -> String {
        let entries: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({ "name": format!("folder-{i:03}"), "size": 1000 + i }))
            .collect();
        serde_json::json!({ "slug": "criterion", "content_types": ["video"], "entries": entries })
            .to_string()
    }

    fn payloads(parts: &[crate::split::ListingPart]) -> Vec<String> {
        parts.iter().map(|p| p.json.clone()).collect()
    }

    #[test]
    fn full_listing_renders_complete_tree() {
        let parts = split_listing("criterion", &listing(30), 256).unwrap();
        let r = render_listing(&payloads(&parts)).unwrap();
        assert!(r.complete(), "all parts present → complete");
        assert_eq!(r.entries.len(), 30, "every folder present");
        assert!(r.missing.is_empty() && r.parts_present == r.parts_total);
        assert_eq!(r.meta.get("slug").unwrap(), "criterion", "metadata preserved");
    }

    #[test]
    fn missing_parts_render_k_of_n_available() {
        let parts = split_listing("criterion", &listing(30), 256).unwrap();
        let mut p = payloads(&parts);
        p.pop(); // withhold the last content part
        let r = render_listing(&p).unwrap();
        assert!(!r.complete(), "a withheld part means incomplete, not an error");
        assert_eq!(r.parts_present, r.parts_total - 1);
        assert_eq!(r.missing.len(), 1, "the one withheld part is reported in `missing`");
        assert!(!r.entries.is_empty(), "the parts that did arrive still render");
    }

    #[test]
    fn withheld_folder_is_marked_unavailable_not_dropped() {
        // Drop a *middle* part — its index must appear in `missing` (so the UI can name it),
        // and the surrounding parts must still render.
        let parts = split_listing("criterion", &listing(30), 200).unwrap();
        let content_count = parts.len() - 1; // minus the index
        assert!(content_count >= 3, "need several parts for a meaningful middle drop");
        let mut p = payloads(&parts);
        p.remove(2); // remove a content part (index 0 is the listing index)
        let r = render_listing(&p).unwrap();
        assert_eq!(r.missing.len(), 1, "exactly one folder marked unavailable");
        assert_eq!(r.parts_present, r.parts_total - 1);
    }

    #[test]
    fn empty_index_is_clean_empty_not_error() {
        // A listing with no entries renders as a complete, empty tree — not an error.
        let parts = split_listing("empty", r#"{"slug":"empty","entries":[]}"#, 65_536).unwrap();
        let r = render_listing(&payloads(&parts)).unwrap();
        assert!(r.complete());
        assert!(r.entries.is_empty());
    }

    #[test]
    fn foreign_part_not_in_index_rejected_with_reason() {
        // A hostile relay injects a content part whose index is outside the index's range.
        let parts = split_listing("criterion", &listing(30), 256).unwrap();
        let n = parts.len() - 1;
        let mut p = payloads(&parts);
        p.push(serde_json::json!({ "part": n + 5, "parts": n, "entries": [] }).to_string());
        match render_listing(&p) {
            Err(NetError::Split(m)) => assert!(m.contains("foreign part"), "got: {m}"),
            other => panic!("expected a foreign-part rejection, got {other:?}"),
        }
    }

    #[test]
    fn part_with_wrong_total_rejected() {
        let parts = split_listing("criterion", &listing(30), 256).unwrap();
        let n = parts.len() - 1;
        let mut p = payloads(&parts);
        p.push(serde_json::json!({ "part": 0, "parts": n + 99, "entries": [] }).to_string());
        match render_listing(&p) {
            Err(NetError::Split(m)) => assert!(m.contains("part claims"), "got: {m}"),
            other => panic!("expected a wrong-total rejection, got {other:?}"),
        }
    }

    #[test]
    fn index_exceeding_max_parts_rejected_before_alloc() {
        // A forged index claiming a huge part count is refused before any per-part allocation.
        let forged = serde_json::json!({
            "slug": "dos", "split": true, "parts": MAX_LISTING_PARTS + 1
        })
        .to_string();
        match render_listing(&[forged]) {
            Err(NetError::Split(m)) => assert!(m.contains("cap"), "got: {m}"),
            other => panic!("expected a parts-cap rejection, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_part_rejected() {
        let parts = split_listing("criterion", &listing(30), 256).unwrap();
        let mut p = payloads(&parts);
        let last = p.len() - 1;
        p[last] = p[1].clone(); // duplicate part 0, drop the real last
        match render_listing(&p) {
            Err(NetError::Split(m)) => assert!(m.contains("duplicate"), "got: {m}"),
            other => panic!("expected a duplicate-part rejection, got {other:?}"),
        }
    }
}
