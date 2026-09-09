// proton-sync/src/contact_plan.rs — Contacts upsync planning (offline, no I/O).
//
// Same cycle semantics as calendar `upsync.rs` (upload → download, fail-closed,
// server-wins conflicts, anchors), with three contacts differences:
//
// 1. NO tombstones: QtContacts has no mKCal-style delete tracking. Deletes
//    come from ID-map diffing — the shim persists `{proton_uid:
//    qcontact_id}` at every save; map entries missing from the current
//    local inventory are user deletes. Nothing is ever purged (no
//    `purgeable` output; the map refreshes from each download).
// 2. No windowed listing: `list_all` fetches everything, so every server
//    row is visible — no UID-fallback needed and no out-of-window gap.
// 3. vCard rebuild (not patch): updates decrypt server cards, overlay the
//    full phone snapshot, rebuild both groups (`contact_seal`). Photos are
//    always preserved from the server (no photo upload v1).
//
// Anchors are server `ModifyTime` per UID. Proton row IDs resolve
// engine-side from fresh listings (planner speaks UIDs; the shim only ever
// sees UIDs in QContactGuid).
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// One local contact as exported by the shim. `proton_uid` is the
/// QContactGuid (`Contact.UID`); `None` = created on the phone, never
/// uploaded. `qcontact_id` is opaque (log/correlation only — the planner
/// never parses it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactItem {
    pub qcontact_id: String,
    #[serde(default)]
    pub proton_uid: Option<String>,
    #[serde(default)]
    pub modified: bool,
    #[serde(default)]
    pub last_synced_mtime: Option<i64>,
    /// Full phone field snapshot (dirty or never-synced rows only).
    #[serde(default)]
    pub fields: Option<proton_api::vcard::ParsedContact>,
}

/// One upload operation, in execution order (creates → updates → deletes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactUploadOp {
    /// Phone-only row → batch create (sealed fresh cards).
    Create { qcontact_id: String },
    /// Known row, locally edited, server untouched → PUT rebuilt cards.
    Update { proton_uid: String },
    /// ID-map entry missing locally, still on server → batch delete.
    Delete { proton_uid: String },
}

/// Both-sides-edited row: server wins, no upload (download overwrites).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactConflict {
    pub proton_uid: String,
    pub qcontact_id: String,
    pub server_mtime: i64,
    pub anchor_mtime: i64,
}

/// The plan for one sync cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactPlan {
    pub uploads: Vec<ContactUploadOp>,
    pub conflicts: Vec<ContactConflict>,
    /// Local rows the server deleted (present locally, absent server-side,
    /// not dirty): the download phase drops them (full replacement does).
    pub apply_server_deletes: Vec<String>,
    /// Map entries already gone on both sides: safe to forget (the shim
    /// prunes them from its persisted map on the next save).
    pub stale_map_entries: Vec<String>,
}

/// Per-UID sync anchors: Proton UID → server `ModifyTime` at the last
/// successful sync.
pub type ContactAnchorMap = HashMap<String, i64>;

/// Merge fresh listing rows into anchors: upsert seen UIDs, prune UIDs in
/// NEITHER fresh rows NOR local inventory.
pub fn merge_contact_anchors(
    old: &ContactAnchorMap,
    fresh: &[proton_api::Contact],
    local_uids: &HashSet<String>,
) -> ContactAnchorMap {
    let mut out = old.clone();
    let mut fresh_uids = HashSet::new();
    for row in fresh {
        fresh_uids.insert(row.UID.clone());
        out.insert(row.UID.clone(), row.ModifyTime);
    }
    out.retain(|uid, _| fresh_uids.contains(uid) || local_uids.contains(uid));
    out
}

/// Build the cycle plan from server rows + local inventory + the persisted
/// ID map (`known_uids`: proton UIDs the shim has ever stored).
/// A lost anchor (`None`) resolves server-wins, like the calendar planner.
pub fn plan_contacts(
    server: &[proton_api::Contact],
    local: &[ContactItem],
    known_uids: &HashSet<String>,
) -> ContactPlan {
    let server_by_uid: HashMap<&str, &proton_api::Contact> =
        server.iter().map(|c| (c.UID.as_str(), c)).collect();
    let mut creates = Vec::new();
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    let mut plan = ContactPlan::default();
    let present: HashSet<&str> = local
        .iter()
        .filter_map(|item| item.proton_uid.as_deref())
        .collect();

    for item in local {
        match &item.proton_uid {
            // Phone-only row → create (dirty flag irrelevant: never synced
            // means the whole content uploads).
            None => creates.push(ContactUploadOp::Create {
                qcontact_id: item.qcontact_id.clone(),
            }),
            Some(uid) => match server_by_uid.get(uid.as_str()) {
                // Gone server-side, kept locally, not dirty → accept.
                None => {
                    plan.apply_server_deletes.push(item.qcontact_id.clone());
                }
                Some(row) => {
                    let anchor = item.last_synced_mtime.unwrap_or(0);
                    let server_changed = row.ModifyTime > anchor;
                    if item.modified && server_changed {
                        plan.conflicts.push(ContactConflict {
                            proton_uid: uid.clone(),
                            qcontact_id: item.qcontact_id.clone(),
                            server_mtime: row.ModifyTime,
                            anchor_mtime: anchor,
                        });
                    } else if item.modified {
                        updates.push(ContactUploadOp::Update {
                            proton_uid: uid.clone(),
                        });
                    }
                }
            },
        }
    }
    // ID-map diffing for deletes (no tombstones in QtContacts): known UIDs
    // missing locally were deleted on the phone.
    for uid in known_uids {
        if present.contains(uid.as_str()) {
            continue;
        }
        match server_by_uid.get(uid.as_str()) {
            Some(_) => deletes.push(ContactUploadOp::Delete {
                proton_uid: uid.clone(),
            }),
            None => plan.stale_map_entries.push(uid.clone()),
        }
    }
    plan.uploads
        .reserve(creates.len() + updates.len() + deletes.len());
    plan.uploads.extend(creates);
    plan.uploads.extend(updates);
    plan.uploads.extend(deletes);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id: &str, uid: &str, mtime: i64) -> proton_api::Contact {
        proton_api::Contact {
            ID: id.into(),
            UID: uid.into(),
            ModifyTime: mtime,
            ..Default::default()
        }
    }

    fn item(qid: &str, uid: Option<&str>, modified: bool, anchor: Option<i64>) -> ContactItem {
        ContactItem {
            qcontact_id: qid.into(),
            proton_uid: uid.map(str::to_string),
            modified,
            last_synced_mtime: anchor,
            fields: None,
        }
    }

    fn known(uids: &[&str]) -> HashSet<String> {
        uids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_empty_plan() {
        let plan = plan_contacts(&[], &[], &known(&[]));
        assert_eq!(plan, ContactPlan::default());
    }

    #[test]
    fn test_phone_create_uploads() {
        // No UID yet → create op in the same cycle that would wipe it.
        let plan = plan_contacts(&[], &[item("q1", None, true, None)], &known(&[]));
        assert_eq!(
            plan.uploads,
            vec![ContactUploadOp::Create {
                qcontact_id: "q1".into()
            }]
        );
    }

    #[test]
    fn test_local_edit_uploads_update() {
        let server = vec![contact("id1", "u1", 100)];
        let plan = plan_contacts(
            &server,
            &[item("q1", Some("u1"), true, Some(100))],
            &known(&["u1"]),
        );
        assert_eq!(
            plan.uploads,
            vec![ContactUploadOp::Update {
                proton_uid: "u1".into()
            }]
        );
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn test_both_sides_edited_conflicts() {
        let server = vec![contact("id1", "u1", 200)];
        let plan = plan_contacts(
            &server,
            &[item("q1", Some("u1"), true, Some(100))],
            &known(&["u1"]),
        );
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].server_mtime, 200);
    }

    #[test]
    fn test_map_diff_delete_uploads() {
        // Known UID missing locally but on server → delete op (no tombstone
        // objects anywhere — the diff IS the delete set).
        let server = vec![contact("id1", "u1", 100)];
        let plan = plan_contacts(&server, &[], &known(&["u1"]));
        assert_eq!(
            plan.uploads,
            vec![ContactUploadOp::Delete {
                proton_uid: "u1".into()
            }]
        );
    }

    #[test]
    fn test_gone_both_sides_forgets() {
        let plan = plan_contacts(&[], &[], &known(&["u9"]));
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.stale_map_entries, vec!["u9".to_string()]);
    }

    #[test]
    fn test_server_delete_applies_locally() {
        let plan = plan_contacts(
            &[],
            &[item("q1", Some("u1"), false, Some(50))],
            &known(&["u1"]),
        );
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.apply_server_deletes, vec!["q1".to_string()]);
    }

    #[test]
    fn test_upload_order_creates_updates_deletes() {
        let server = vec![
            contact("a", "ua", 1),
            contact("b", "ub", 1),
            contact("d", "ud", 1),
        ];
        let plan = plan_contacts(
            &server,
            &[
                item("qd", Some("ub"), false, None),
                item("qc", None, false, None),
                item("qu", Some("ua"), true, Some(1)),
            ],
            &known(&["ua", "ub", "ud"]),
        );
        // ub present locally (not dirty) → nothing; ud known but missing
        // locally → delete. Order: creates, updates, deletes.
        assert_eq!(
            plan.uploads,
            vec![
                ContactUploadOp::Create {
                    qcontact_id: "qc".into()
                },
                ContactUploadOp::Update {
                    proton_uid: "ua".into()
                },
                ContactUploadOp::Delete {
                    proton_uid: "ud".into()
                },
            ]
        );
    }

    #[test]
    fn test_anchors_merge_and_prune() {
        let mut old = ContactAnchorMap::new();
        old.insert("keep".into(), 10);
        old.insert("gone".into(), 10);
        let fresh = vec![contact("a", "keep", 20)];
        let mut local = HashSet::new();
        local.insert("keep".into());
        let merged = merge_contact_anchors(&old, &fresh, &local);
        assert_eq!(merged.get("keep"), Some(&20));
        assert!(!merged.contains_key("gone"));
    }

    #[test]
    fn test_inventory_json_contract() {
        let item = item("q1", Some("u1"), true, Some(100));
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["qcontact_id"], "q1");
        assert_eq!(v["proton_uid"], "u1");
        let back: ContactItem = serde_json::from_value(v).unwrap();
        assert_eq!(back, item);
    }
}
