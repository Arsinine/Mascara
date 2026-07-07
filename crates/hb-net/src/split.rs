//! Oversize-listing split / restitch (N4; spec §Data Model split-listing protocol, HANDOVER
//! §C). A relay caps event size (strfry default 64 KiB), so a large collection listing is split
//! into an **index part** plus per-chunk **content parts**, each a separately-published
//! parameterized-replaceable event, and re-stitched into the full tree on fetch.
//!
//! The listing payload is a JSON object with an `entries` array (the top-level folders/files);
//! every other top-level field (slug, content_types, …) is metadata preserved verbatim. When the
//! whole payload fits, it is published as a single event under `d = <slug>`. When it doesn't, the
//! `entries` are chunked under a byte budget; the index records the **part count** so a fetcher
//! knows how many to collect and can report "N of M parts available" on loss.
//!
//! Per-part `sha256` integrity (spec) is intentionally deferred to M3: each part is already a
//! Schnorr-signed listing event (tamper-evident at the event layer), so M2's split protocol
//! carries only the index→parts linkage that restitch needs. Recorded in HANDOVER.

use serde_json::{Map, Value};

use crate::error::NetError;

/// One published unit of a (possibly split) listing: the parameterized-replaceable `d`
/// identifier its event carries, and the plaintext JSON payload to encrypt + publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingPart {
    pub d_tag: String,
    pub json: String,
}

/// The `d`-tag of content part `i` for a given slug (deterministic so a fetcher can address them).
fn part_d_tag(slug: &str, i: usize) -> String {
    format!("{slug}#part{i}")
}

/// Normalise a JSON payload to its canonical (sorted-key) string form, so split→restitch is a
/// byte-exact round-trip regardless of input key order.
fn normalize(json: &str) -> Result<String, NetError> {
    let v: Value = serde_json::from_str(json).map_err(|e| NetError::Split(e.to_string()))?;
    serde_json::to_string(&v).map_err(|e| NetError::Split(e.to_string()))
}

/// Split a listing payload into publishable parts under a `max_bytes` budget on each part's JSON.
///
/// A payload that fits returns a single part under `d = slug`. An oversize payload returns an
/// index part (`d = slug`, recording `split: true` + `parts: N` + the preserved metadata) plus
/// N content parts (`d = slug#partI`) carrying chunks of `entries`.
pub fn split_listing(
    slug: &str,
    listing_json: &str,
    max_bytes: usize,
) -> Result<Vec<ListingPart>, NetError> {
    let normalized = normalize(listing_json)?;
    if normalized.len() <= max_bytes {
        return Ok(vec![ListingPart { d_tag: slug.to_string(), json: normalized }]);
    }

    // Operate on the canonical form the fast path already produced (coherent with this
    // function's contract; guaranteed to re-parse since `normalize` validated it).
    let value: Value = serde_json::from_str(&normalized).map_err(|e| NetError::Split(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| NetError::Split("listing payload is not a JSON object".into()))?;
    let entries = obj
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| NetError::Split("oversize listing has no `entries` array to split".into()))?;

    // Metadata = every top-level field except `entries`, preserved verbatim into the index.
    let mut meta: Map<String, Value> = obj.clone();
    meta.remove("entries");

    // Chunk entries greedily under the byte budget (a lone entry bigger than the budget still
    // gets its own part — it can't be split further at this level).
    let mut chunks: Vec<Vec<Value>> = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    for entry in entries {
        current.push(entry.clone());
        // Measure with worst-case marker widths so a tight chunk can't exceed max_bytes once the
        // real (possibly multi-digit) part/parts indices are substituted.
        let part_len = content_part_json(&current, usize::MAX, usize::MAX)?.len();
        if part_len > max_bytes && current.len() > 1 {
            let last = current.pop().unwrap();
            chunks.push(std::mem::take(&mut current));
            current.push(last);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    let n = chunks.len();

    let mut parts = Vec::with_capacity(n + 1);
    // Index part.
    let mut index = meta;
    index.insert("split".into(), Value::Bool(true));
    index.insert("parts".into(), Value::from(n));
    parts.push(ListingPart {
        d_tag: slug.to_string(),
        json: serde_json::to_string(&Value::Object(index)).map_err(|e| NetError::Split(e.to_string()))?,
    });
    // Content parts.
    for (i, chunk) in chunks.into_iter().enumerate() {
        parts.push(ListingPart {
            d_tag: part_d_tag(slug, i),
            json: content_part_json(&chunk, i, n)?,
        });
    }
    Ok(parts)
}

fn content_part_json(entries: &[Value], part: usize, parts: usize) -> Result<String, NetError> {
    let mut m = Map::new();
    m.insert("part".into(), Value::from(part));
    m.insert("parts".into(), Value::from(parts));
    m.insert("entries".into(), Value::Array(entries.to_vec()));
    serde_json::to_string(&Value::Object(m)).map_err(|e| NetError::Split(e.to_string()))
}

/// Re-stitch fetched part payloads into the full listing. A single unsplit part is returned
/// as-is; otherwise the index supplies the part count + metadata and the content parts supply
/// the `entries`. A missing **or duplicate** content part is reported as an error (the spec's
/// "N of M folders available on loss"), never a silent partial/corrupt tree.
///
/// `parts` is the set of decrypted JSON payloads (the `d` tag is not needed — parts self-index
/// via their `part`/`parts` markers). **The caller must pass payloads from
/// signature-verified+decrypted events** (e.g. via `parse_listing_event`): this function trusts
/// the JSON it is given and does not verify provenance.
pub fn restitch_listing(parts: &[String]) -> Result<String, NetError> {
    if parts.is_empty() {
        return Err(NetError::Split("no parts to restitch".into()));
    }

    // Locate the index (split == true). A lone part with no split marker is the whole listing.
    let mut index: Option<Map<String, Value>> = None;
    let mut content: Vec<(usize, usize, Vec<Value>)> = Vec::new();
    for json in parts {
        let v: Value = serde_json::from_str(json).map_err(|e| NetError::Split(e.to_string()))?;
        let obj = v.as_object().ok_or_else(|| NetError::Split("part is not an object".into()))?;
        if obj.get("split") == Some(&Value::Bool(true)) {
            index = Some(obj.clone());
        } else if let Some(entries) = obj.get("entries").and_then(Value::as_array) {
            let part = obj.get("part").and_then(Value::as_u64);
            let total = obj.get("parts").and_then(Value::as_u64);
            match (part, total) {
                (Some(p), Some(t)) => content.push((p as usize, t as usize, entries.clone())),
                // No part markers → an unsplit single listing; return it normalized.
                _ if parts.len() == 1 => return normalize(json),
                _ => return Err(NetError::Split("content part missing part/parts markers".into())),
            }
        } else if parts.len() == 1 {
            return normalize(json); // single unsplit part with no entries (e.g. empty listing)
        }
    }

    let index = index.ok_or_else(|| NetError::Split("no index part found".into()))?;
    let n = index
        .get("parts")
        .and_then(Value::as_u64)
        .ok_or_else(|| NetError::Split("index missing part count".into()))? as usize;

    if content.len() != n {
        return Err(NetError::Split(format!("got {} of {} parts", content.len(), n)));
    }
    // Parts must be exactly {0,1,…,n-1}, each present once — so a hostile relay can't slip in
    // duplicate part numbers (which would pass the count check while a real part is missing).
    content.sort_by_key(|(p, _, _)| *p);
    let mut entries: Vec<Value> = Vec::new();
    for (i, (p, total, chunk)) in content.into_iter().enumerate() {
        if p != i {
            return Err(NetError::Split(format!("missing or duplicate part: expected {i}, got {p}")));
        }
        if total != n {
            return Err(NetError::Split(format!("part claims {total} parts, index says {n}")));
        }
        entries.extend(chunk);
    }

    let mut full: Map<String, Value> = index;
    full.remove("split");
    full.remove("parts");
    full.insert("entries".into(), Value::Array(entries));
    serde_json::to_string(&Value::Object(full)).map_err(|e| NetError::Split(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A listing with `n` folder entries, each padded so the whole payload is comfortably large.
    fn listing(n: usize) -> String {
        let entries: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({ "name": format!("folder-{i:03}"), "size": 1_000_000 + i }))
            .collect();
        serde_json::json!({
            "slug": "criterion",
            "content_types": ["video"],
            "entries": entries,
        })
        .to_string()
    }

    #[test]
    fn small_listing_is_single_part() {
        let parts = split_listing("criterion", &listing(2), 65_536).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].d_tag, "criterion");
        assert!(!parts[0].json.contains("\"split\""), "a fitting listing carries no split marker");
    }

    #[test]
    fn oversize_listing_splits_per_folder() {
        // A tight budget forces multiple content parts.
        let parts = split_listing("criterion", &listing(40), 256).unwrap();
        assert!(parts.len() > 2, "expected an index + several content parts, got {}", parts.len());
        // The index leads; content parts stay within budget.
        assert_eq!(parts[0].d_tag, "criterion");
        assert!(parts[0].json.contains("\"split\":true"));
        for p in &parts[1..] {
            assert!(p.json.len() <= 256, "content part {} exceeds budget: {} bytes", p.d_tag, p.json.len());
        }
    }

    fn payloads(parts: &[ListingPart]) -> Vec<String> {
        parts.iter().map(|p| p.json.clone()).collect()
    }

    #[test]
    fn split_listing_restitches_to_full_tree() {
        let original = listing(40);
        let parts = split_listing("criterion", &original, 256).unwrap();
        let restitched = restitch_listing(&payloads(&parts)).unwrap();
        assert_eq!(restitched, normalize(&original).unwrap(), "restitch must reproduce the full tree");
    }

    #[test]
    fn restitch_single_unsplit_part() {
        let original = listing(2);
        let parts = split_listing("criterion", &original, 65_536).unwrap();
        assert_eq!(restitch_listing(&payloads(&parts)).unwrap(), normalize(&original).unwrap());
    }

    #[test]
    fn restitch_detects_missing_part() {
        let parts = split_listing("criterion", &listing(40), 256).unwrap();
        // Drop one content part → restitch refuses with an "N of M" report.
        let mut fetched = payloads(&parts);
        fetched.pop();
        match restitch_listing(&fetched) {
            Err(NetError::Split(m)) => assert!(m.contains(" of "), "expected 'K of N', got: {m}"),
            other => panic!("expected a missing-part error, got {other:?}"),
        }
    }

    #[test]
    fn restitch_rejects_duplicate_part() {
        // A hostile relay returns the right *count* of parts but a duplicate part number and a
        // missing one → must be refused, not silently restitched into a corrupt tree.
        let parts = split_listing("criterion", &listing(40), 256).unwrap();
        let mut fetched = payloads(&parts);
        let last = fetched.len() - 1;
        fetched[last] = fetched[1].clone(); // replace the last content part with a copy of part 0
        match restitch_listing(&fetched) {
            Err(NetError::Split(m)) => assert!(m.contains("duplicate"), "expected duplicate error, got: {m}"),
            other => panic!("expected a duplicate-part error, got {other:?}"),
        }
    }
}
