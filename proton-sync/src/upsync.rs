// proton-sync/src/upsync.rs — Upsync change planning (offline, no I/O).
//
// Decides WHAT to upload from a server row list + a local inventory the
// shim exports (mKCal incidences incl. tombstones). Pure logic; the engine
// (wiring phase) will feed it and execute the plan. Researched 2026-09-07,
// see FINDINGS_CALENDAR.md §12–§13.
//
// The race from the 2026-09-07 review ("local create wiped by the next sync
// before upload") is closed by construction here, not by speed:
//
//  1. The shim NEVER blind-deletes anymore once this plan drives the cycle:
//     local changes become upload ops in the SAME cycle that would otherwise
//     wipe them.
//  2. Phase order is fixed (see `SyncCycle::ORDER`): upload creates →
//     updates → deletes, and ONLY after every upload succeeds may the shim
//     purge the listed tombstones and apply downloads. Any upload failure
//     aborts before local state is touched (fail-closed).
//  3. Tombstones are upload inputs, not garbage: a deleted local row WITH a
//     Proton ID uploads a server delete; only then is its tombstone listed
//     in `purgeable_tombstones`. (Today's shim purges unconditionally —
//     that discipline MUST change with wiring; until then this planner is
//     inert.)
//
// Conflict policy (v1, download-primary product): server wins. A row edited
// on BOTH sides since the anchor is recorded in `conflicts` and NOT
// uploaded; the download phase overwrites it locally.
//
// Anchors: the server offers no sync tokens, so the per-row anchor is the
// `LastEditTime` seen at the last successful sync (stored by the shim in
// QSettings next to tokens/defaults in the wiring phase). A row newer than
// its anchor changed server-side. A LOST anchor (None) is treated as
// "server changed" — ambiguous state resolves server-wins, consistent with
// server-side deletes being applied locally.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// One local incidence as exported by the shim: live rows plus tombstones
/// from `deletedIncidences`. `proton_id` is the `X-PROTON-EVENT-ID` custom
/// property (`None` = created locally, never uploaded). Serialized as the
/// shim↔engine inventory JSON contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalItem {
    /// mKCal UID (namespaced `proton-cal-<acct>-…`, exception standalones
    /// carry the `<uid>#<rid>` suffix form).
    pub mkcal_uid: String,
    /// Proton row event ID (`CalendarEvent.ID`), if ever synced.
    pub proton_id: Option<String>,
    /// Tombstone: the user deleted this row locally.
    pub deleted: bool,
    /// Changed locally since the last successful sync (shim dirty flag;
    /// always false for tombstones).
    pub modified: bool,
    /// Server `LastEditTime` recorded at the last successful sync.
    pub last_synced_mtime: Option<i64>,
    /// Local field snapshot (dirty or never-synced rows only; `None`
    /// otherwise). Drives update patching / create building.
    #[serde(default)]
    pub fields: Option<proton_api::calendar_write::LocalFields>,
    /// Proton calendar ID owning the row (parsed by the shim from the
    /// notebook UID; needed to route creates, which have no server row).
    #[serde(default)]
    pub calendar_id: Option<String>,
}

/// One upload operation (phase 1), in plan order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UploadOp {
    /// Local-only row → sync create (full sealed body).
    Create { mkcal_uid: String },
    /// Known row, locally edited, server untouched → sync update (patched
    /// reseal of `proton_id`).
    Update {
        proton_id: String,
        mkcal_uid: String,
    },
    /// Tombstone with a Proton ID → sync delete of `proton_id`.
    Delete { proton_id: String },
}

/// Both-sides-edited row: server wins, no upload; the download phase
/// overwrites the local row (recorded so the UI can notify).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflict {
    pub proton_id: String,
    pub mkcal_uid: String,
    pub server_mtime: i64,
    pub anchor_mtime: i64,
}

/// The plan for one sync cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncPlan {
    /// Uploads in execution order: creates → updates → deletes (updates
    /// before deletes: a master time/rule change and its invalidated
    /// exception deletes travel together, master first).
    pub uploads: Vec<UploadOp>,
    /// Server-wins rows (download overwrites them; never uploaded).
    pub conflicts: Vec<SyncConflict>,
    /// Local rows the server deleted (absent server-side, present locally,
    /// not dirty): the download phase drops them.
    pub apply_server_deletes: Vec<String>,
    /// mKCal UIDs whose tombstones may be purged — ONLY after every upload
    /// in `uploads` succeeded. Includes never-uploaded orphans (nothing to
    /// push for them; purging is safe once planning saw them).
    pub purgeable_tombstones: Vec<String>,
    /// Tombstones that never reached the server (created then deleted
    /// locally between syncs): dropped silently, counted for the log.
    pub orphan_local_deletes: u32,
}

/// Scrubbed one-line summary of a sync batch for failure logs: op IDs,
/// part-type lists, Notifications/Color presence. NEVER includes Data,
/// Signature, or key packets (bulky ciphertext) nor any plaintext — safe
/// for the world-readable debug log.
pub fn scrub_batch(batch: &proton_api::SyncBatchRequest) -> String {
    let ops: Vec<String> = batch
        .Events
        .iter()
        .map(|op| match (&op.ID, &op.Overwrite, &op.Event) {
            (Some(id), _, None) => format!("del({id})"),
            (Some(id), _, Some(body)) => format!(
                "upd({id} shared={:?} cal={:?} notif={} color={})",
                body.SharedEventContent
                    .iter()
                    .map(|p| p.Type)
                    .collect::<Vec<_>>(),
                body.CalendarEventContent
                    .iter()
                    .map(|p| p.Type)
                    .collect::<Vec<_>>(),
                !body.Notifications.is_null(),
                !body.Color.is_null(),
            ),
            (None, _, Some(body)) => format!(
                "create(shared={} cal={})",
                body.SharedEventContent.len(),
                body.CalendarEventContent.len(),
            ),
            _ => "op(?)".into(),
        })
        .collect();
    format!("member={} ops=[{}]", batch.MemberID, ops.join(" "))
}

/// Fixed cycle order. Upload failures abort before purge/download (the
/// fail-closed rule from the race-condition review).
pub struct SyncCycle;

impl SyncCycle {
    /// Phase order: uploads → tombstone purge → downloads → anchor store.
    pub const ORDER: [&'static str; 4] =
        ["upload", "purge_tombstones", "download", "store_anchors"];
}

/// All Proton row IDs sharing one iCal UID (master + exception rows), for
/// series-delete completeness: deleting a master ORPHANS its exceptions
/// (no server cascade), so one batch must carry them all
/// (`SyncBatchRequest::delete_batch`).
pub fn ids_for_uid(rows: &[proton_api::CalendarEvent], uid: &str) -> Vec<String> {
    rows.iter()
        .filter(|r| r.UID == uid)
        .map(|r| r.ID.clone())
        .collect()
}

/// Per-row sync anchors: Proton row ID → server `LastEditTime` seen at the
/// last successful sync. The server offers no sync tokens; row mtimes are
/// the poor-man's anchor (see module docs). Persisted by the shim in
/// QSettings next to tokens/defaults; fed back via `SyncConfig` at wiring.
pub type AnchorMap = HashMap<String, i64>;

/// Merge fresh listing rows into the anchor map: upsert seen IDs, prune IDs
/// in NEITHER the fresh rows NOR the local inventory (fully gone on both
/// sides — safe to forget). Never prune merely-unlisted IDs: our listing
/// covers a 2-year window, so absence is not deletion.
pub fn merge_anchors(
    old: &AnchorMap,
    fresh: &[proton_api::CalendarEvent],
    local_ids: &HashSet<String>,
) -> AnchorMap {
    let mut out = old.clone();
    let mut fresh_ids = HashSet::new();
    for row in fresh {
        fresh_ids.insert(row.ID.clone());
        out.insert(row.ID.clone(), row.LastEditTime);
    }
    out.retain(|id, _| fresh_ids.contains(id) || local_ids.contains(id));
    out
}

/// Assemble the delete batch for a plan: every `Delete` op expands to its
/// full same-UID series (via `ids_for_uid`), deduped, plan order kept.
/// Unknown IDs (row vanished between planning and batching) pass through
/// as-is — the server ignores unknown delete IDs.
pub fn assemble_delete_batch(
    member_id: &str,
    plan: &SyncPlan,
    server: &[proton_api::CalendarEvent],
) -> Option<proton_api::SyncBatchRequest> {
    let by_id: HashMap<&str, &proton_api::CalendarEvent> =
        server.iter().map(|r| (r.ID.as_str(), r)).collect();
    let mut ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for op in &plan.uploads {
        let UploadOp::Delete { proton_id } = op else {
            continue;
        };
        let group = match by_id.get(proton_id.as_str()) {
            Some(row) => ids_for_uid(server, &row.UID),
            None => vec![proton_id.clone()],
        };
        for id in group {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }
    }
    if ids.is_empty() {
        return None;
    }
    Some(proton_api::SyncBatchRequest::delete_batch(member_id, &ids))
}

/// Assemble an update batch from pre-sealed bodies (keyed by event ID).
/// Sealing (patch + reseal) happens in the engine; this only shapes the
/// `{ID, Event}` ops in the given order.
pub fn assemble_update_batch(
    member_id: &str,
    sealed: Vec<(String, proton_api::SyncEventBody)>,
) -> Option<proton_api::SyncBatchRequest> {
    if sealed.is_empty() {
        return None;
    }
    Some(proton_api::SyncBatchRequest {
        MemberID: member_id.to_string(),
        IsImport: None,
        Events: sealed
            .into_iter()
            .map(|(id, body)| proton_api::SyncEventOp::update(&id, body))
            .collect(),
    })
}

/// Outcome of the upload phase (phase 1). Fail-closed: the first failing
/// batch stops the phase; later batches never send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadSummary {
    pub completed_batches: usize,
    pub completed_ops: usize,
    pub error: Option<String>,
}

/// Execute upload batches in order, stopping at the first failure
/// (transport error or `first_error` in the response). The transport is a
/// closure so this stays offline-testable; the engine passes
/// `|batch| client.put_sync(cal_id, batch).map_err(...)` at wiring.
pub fn execute_uploads(
    put: &mut dyn FnMut(
        &proton_api::SyncBatchRequest,
    ) -> Result<proton_api::SyncBatchResponse, String>,
    batches: &[proton_api::SyncBatchRequest],
) -> UploadSummary {
    let mut summary = UploadSummary::default();
    for batch in batches {
        match put(batch) {
            Ok(resp) => {
                if let Some(err) = resp.first_error() {
                    summary.error = Some(err);
                    return summary;
                }
                summary.completed_batches += 1;
                summary.completed_ops += batch.Events.len();
            }
            Err(e) => {
                summary.error = Some(e);
                return summary;
            }
        }
    }
    summary
}

/// Build the cycle plan from server rows + local inventory.
pub fn plan_sync(server: &[proton_api::CalendarEvent], local: &[LocalItem]) -> SyncPlan {
    let server_by_id: HashMap<&str, &proton_api::CalendarEvent> =
        server.iter().map(|r| (r.ID.as_str(), r)).collect();
    let mut creates = Vec::new();
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    let mut plan = SyncPlan::default();
    let mut seen_proton: HashSet<&str> = HashSet::new();

    for item in local {
        match (&item.proton_id, item.deleted) {
            // Created AND deleted locally between syncs: never existed
            // server-side. Nothing to upload; tombstone purgable.
            (None, true) => {
                plan.orphan_local_deletes += 1;
                plan.purgeable_tombstones.push(item.mkcal_uid.clone());
            }
            // Local-only row → create (dirty flag irrelevant: never synced
            // means the whole content uploads).
            (None, false) => creates.push(UploadOp::Create {
                mkcal_uid: item.mkcal_uid.clone(),
            }),
            // Tombstone of a synced row → server delete, then purgeable.
            // Already gone server-side → desired end state reached: NO
            // upload (unknown-ID deletes have undefined server semantics
            // and a per-op error would fail the phase closed for nothing),
            // tombstone still purgeable. Out-of-window rows share this
            // path — deleting never-listed old events via the phone is a
            // known v1 limitation (documented in §12).
            (Some(pid), true) => {
                plan.purgeable_tombstones.push(item.mkcal_uid.clone());
                if server_by_id.contains_key(pid.as_str()) {
                    deletes.push(UploadOp::Delete {
                        proton_id: pid.clone(),
                    });
                }
            }
            (Some(pid), false) => {
                seen_proton.insert(pid.as_str());
                let Some(row) = server_by_id.get(pid.as_str()) else {
                    // Gone server-side, kept locally, not dirty → accept
                    // the server delete on download (v1 server-wins).
                    plan.apply_server_deletes.push(item.mkcal_uid.clone());
                    continue;
                };
                // Lost anchor = ambiguous → treat as server-changed
                // (resolves server-wins, documented above).
                let anchor = item.last_synced_mtime.unwrap_or(0);
                let server_changed = row.LastEditTime > anchor;
                if item.modified && server_changed {
                    plan.conflicts.push(SyncConflict {
                        proton_id: pid.clone(),
                        mkcal_uid: item.mkcal_uid.clone(),
                        server_mtime: row.LastEditTime,
                        anchor_mtime: anchor,
                    });
                } else if item.modified {
                    updates.push(UploadOp::Update {
                        proton_id: pid.clone(),
                        mkcal_uid: item.mkcal_uid.clone(),
                    });
                }
                // Else: untouched locally → download phase applies server
                // state when newer; no upload either way.
            }
        }
    }
    // Server rows the shim never stored (fresh server creates) need no
    // upload entry — the download phase adds them. But rows unknown to BOTH
    // the inventory and... nothing: `seen_proton` guards future use (e.g.
    // detecting inventory gaps); keep the computation cheap and explicit.
    let _ = seen_proton;

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

    fn row(id: &str, uid: &str, mtime: i64) -> proton_api::CalendarEvent {
        proton_api::CalendarEvent {
            ID: id.into(),
            UID: uid.into(),
            LastEditTime: mtime,
            ..Default::default()
        }
    }

    fn local(
        mkcal_uid: &str,
        proton_id: Option<&str>,
        deleted: bool,
        modified: bool,
        anchor: Option<i64>,
    ) -> LocalItem {
        LocalItem {
            mkcal_uid: mkcal_uid.into(),
            proton_id: proton_id.map(str::to_string),
            deleted,
            modified,
            last_synced_mtime: anchor,
            fields: None,
            calendar_id: None,
        }
    }

    #[test]
    fn test_empty_plan() {
        let plan = plan_sync(&[], &[]);
        assert_eq!(plan, SyncPlan::default());
    }

    #[test]
    fn test_local_create_uploads() {
        // The race-condition case: a locally created event becomes a create
        // op in the SAME cycle that would otherwise wipe it.
        let plan = plan_sync(&[], &[local("n1", None, false, true, None)]);
        assert_eq!(
            plan.uploads,
            vec![UploadOp::Create {
                mkcal_uid: "n1".into()
            }]
        );
        assert!(plan.conflicts.is_empty());
        assert!(plan.purgeable_tombstones.is_empty());
    }

    #[test]
    fn test_clean_rows_upload_nothing() {
        let server = vec![row("e1", "u1", 100)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), false, false, Some(100))]);
        assert!(plan.uploads.is_empty());
        assert!(plan.conflicts.is_empty());
        // Server unchanged since anchor → no download either.
    }

    #[test]
    fn test_local_edit_uploads_update() {
        let server = vec![row("e1", "u1", 100)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), false, true, Some(100))]);
        assert_eq!(
            plan.uploads,
            vec![UploadOp::Update {
                proton_id: "e1".into(),
                mkcal_uid: "n1".into(),
            }]
        );
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn test_both_sides_edited_conflicts_server_wins() {
        let server = vec![row("e1", "u1", 200)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), false, true, Some(100))]);
        assert!(plan.uploads.is_empty(), "conflicted rows never upload");
        assert_eq!(
            plan.conflicts,
            vec![SyncConflict {
                proton_id: "e1".into(),
                mkcal_uid: "n1".into(),
                server_mtime: 200,
                anchor_mtime: 100,
            }]
        );
    }

    #[test]
    fn test_server_edit_alone_downloads_silently() {
        let server = vec![row("e1", "u1", 200)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), false, false, Some(100))]);
        assert!(plan.uploads.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn test_server_delete_applies_locally() {
        let plan = plan_sync(&[], &[local("n1", Some("e9"), false, false, Some(50))]);
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.apply_server_deletes, vec!["n1".to_string()]);
    }

    #[test]
    fn test_tombstone_uploads_delete_then_purgeable() {
        // Tombstones are upload INPUTS: delete first, purge only after the
        // upload phase succeeds (never unconditionally like today).
        let server = vec![row("e1", "u1", 100)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), true, false, Some(100))]);
        assert_eq!(
            plan.uploads,
            vec![UploadOp::Delete {
                proton_id: "e1".into()
            }]
        );
        assert_eq!(plan.purgeable_tombstones, vec!["n1".to_string()]);
    }

    #[test]
    fn test_tombstone_of_gone_row_skips_upload() {
        // Already gone server-side = desired end state: no upload (unknown
        // IDs must never reach the wire), tombstone still purgeable.
        let server = vec![row("e1", "u1", 100)];
        let plan = plan_sync(&server, &[local("n9", Some("e9"), true, false, Some(50))]);
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.purgeable_tombstones, vec!["n9".to_string()]);
    }

    #[test]
    fn test_orphan_delete_dropped_silently() {
        let plan = plan_sync(&[], &[local("n1", None, true, false, None)]);
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.orphan_local_deletes, 1);
        assert_eq!(plan.purgeable_tombstones, vec!["n1".to_string()]);
    }

    #[test]
    fn test_upload_order_updates_before_deletes() {
        let server = vec![row("e1", "u1", 100), row("e2", "u2", 100)];
        let plan = plan_sync(
            &server,
            &[
                local("nd", Some("e2"), true, false, Some(100)),
                local("nc", None, false, false, None),
                local("nu", Some("e1"), false, true, Some(100)),
            ],
        );
        // Creates → updates → deletes regardless of inventory order.
        assert_eq!(
            plan.uploads,
            vec![
                UploadOp::Create {
                    mkcal_uid: "nc".into()
                },
                UploadOp::Update {
                    proton_id: "e1".into(),
                    mkcal_uid: "nu".into(),
                },
                UploadOp::Delete {
                    proton_id: "e2".into()
                },
            ]
        );
    }

    #[test]
    fn test_lost_anchor_resolves_server_wins() {
        // Anchor wiped (QSettings loss) + local edit: ambiguous → no upload,
        // conflict recorded (consistent with server-wins product rule).
        let server = vec![row("e1", "u1", 100)];
        let plan = plan_sync(&server, &[local("n1", Some("e1"), false, true, None)]);
        assert!(plan.uploads.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
    }

    #[test]
    fn test_ids_for_uid_groups_series() {
        let rows = vec![row("e1", "u1", 1), row("e2", "u1", 2), row("e3", "u9", 3)];
        assert_eq!(
            ids_for_uid(&rows, "u1"),
            vec!["e1".to_string(), "e2".to_string()]
        );
        assert!(ids_for_uid(&rows, "missing").is_empty());
    }

    #[test]
    fn test_scrub_batch_hides_blobs() {
        use proton_api::{SyncContentPart, SyncEventBody, SyncEventOp};
        let batch = proton_api::SyncBatchRequest {
            MemberID: "m1".into(),
            IsImport: None,
            Events: vec![
                SyncEventOp::delete("e9"),
                SyncEventOp::update(
                    "e1",
                    SyncEventBody {
                        Permissions: 1,
                        SharedKeyPacket: None,
                        CalendarKeyPacket: None,
                        SharedEventContent: vec![
                            SyncContentPart {
                                Type: 2,
                                Data: "SECRET-PLAIN".into(),
                                Signature: "SECRET-SIG".into(),
                            },
                            SyncContentPart {
                                Type: 3,
                                Data: "SECRET-BLOB".into(),
                                Signature: "SECRET-SIG".into(),
                            },
                        ],
                        CalendarEventContent: Vec::new(),
                        AttendeesEventContent: Vec::new(),
                        Attendees: serde_json::json!([]),
                        Notifications: serde_json::json!([{"Trigger": "-PT15M"}]),
                        Color: serde_json::Value::Null,
                    },
                ),
            ],
        };
        let s = scrub_batch(&batch);
        assert!(s.contains("del(e9)"), "{s}");
        assert!(s.contains("upd(e1"), "{s}");
        assert!(s.contains("notif=true"), "{s}");
        for secret in ["SECRET-PLAIN", "SECRET-BLOB", "SECRET-SIG"] {
            assert!(!s.contains(secret), "{s}");
        }
    }

    #[test]
    fn test_cycle_order_is_upload_first() {
        assert_eq!(
            SyncCycle::ORDER,
            ["upload", "purge_tombstones", "download", "store_anchors"]
        );
    }

    #[test]
    fn test_merge_anchors_upserts_and_prunes_gone() {
        let mut old = AnchorMap::new();
        old.insert("keep".into(), 10);
        old.insert("gone".into(), 10);
        old.insert("unlisted".into(), 10);
        let fresh = vec![row("keep", "u1", 20), row("new", "u2", 5)];
        let mut local_ids = HashSet::new();
        local_ids.insert("unlisted".into());
        let merged = merge_anchors(&old, &fresh, &local_ids);
        // Seen rows refresh; unlisted-but-local survives (window != delete);
        // gone-everywhere prunes.
        assert_eq!(merged.get("keep"), Some(&20));
        assert_eq!(merged.get("new"), Some(&5));
        assert_eq!(merged.get("unlisted"), Some(&10));
        assert!(!merged.contains_key("gone"));
    }

    #[test]
    fn test_assemble_delete_batch_expands_series() {
        let server = vec![row("e1", "u1", 1), row("e2", "u1", 2), row("e3", "u9", 3)];
        let plan = SyncPlan {
            uploads: vec![
                UploadOp::Delete {
                    proton_id: "e1".into(),
                },
                UploadOp::Delete {
                    proton_id: "e3".into(),
                },
            ],
            ..Default::default()
        };
        let batch = assemble_delete_batch("m1", &plan, &server).unwrap();
        // e1 expands to its full series (e1+e2, no orphans); e3 alone.
        let ids: Vec<&str> = batch
            .Events
            .iter()
            .map(|op| op.ID.as_deref().unwrap())
            .collect();
        assert_eq!(ids, vec!["e1", "e2", "e3"]);
        assert_eq!(batch.MemberID, "m1");
        assert!(batch.IsImport.is_none());
    }

    #[test]
    fn test_assemble_delete_batch_unknown_id_passes_through() {
        let plan = SyncPlan {
            uploads: vec![UploadOp::Delete {
                proton_id: "vanished".into(),
            }],
            ..Default::default()
        };
        let batch = assemble_delete_batch("m1", &plan, &[]).unwrap();
        assert_eq!(batch.Events.len(), 1);
        assert_eq!(batch.Events[0].ID.as_deref(), Some("vanished"));
    }

    #[test]
    fn test_assemble_batches_none_when_empty() {
        let plan = SyncPlan::default();
        assert!(assemble_delete_batch("m1", &plan, &[]).is_none());
        assert!(assemble_update_batch("m1", Vec::new()).is_none());
    }

    #[test]
    fn test_assemble_update_batch_shapes_ops() {
        use proton_api::{SyncContentPart, SyncEventBody};
        let body = SyncEventBody {
            Permissions: 1,
            SharedKeyPacket: None,
            CalendarKeyPacket: None,
            SharedEventContent: vec![SyncContentPart {
                Type: 2,
                Data: "x".into(),
                Signature: "s".into(),
            }],
            CalendarEventContent: Vec::new(),
            AttendeesEventContent: Vec::new(),
            Attendees: serde_json::json!([]),
            Notifications: serde_json::Value::Null,
            Color: serde_json::Value::Null,
        };
        let batch = assemble_update_batch("m1", vec![("e1".to_string(), body)]).unwrap();
        assert_eq!(batch.Events.len(), 1);
        assert_eq!(batch.Events[0].ID.as_deref(), Some("e1"));
        assert!(batch.Events[0].Overwrite.is_none());
        assert!(batch.IsImport.is_none());
    }

    #[test]
    fn test_execute_uploads_stops_at_first_failure() {
        use proton_api::{SyncBatchRequest, SyncBatchResponse, SyncEventOp};
        let ok = || SyncBatchResponse {
            Code: 1001,
            Responses: Vec::new(),
        };
        let fail = || SyncBatchResponse {
            Code: 1001,
            Responses: vec![proton_api::SyncOpResponse {
                Index: 0,
                Response: proton_api::SyncOpResult {
                    Code: 2001,
                    Error: "bad sequence".into(),
                    Event: None,
                },
            }],
        };
        let batch = |id: &str| SyncBatchRequest {
            MemberID: "m".into(),
            IsImport: None,
            Events: vec![SyncEventOp::delete(id)],
        };
        let batches = vec![batch("a"), batch("b"), batch("c")];
        let mut calls = 0;
        let mut put = |_: &SyncBatchRequest| -> Result<SyncBatchResponse, String> {
            calls += 1;
            if calls == 2 {
                Ok(fail())
            } else {
                Ok(ok())
            }
        };
        let summary = execute_uploads(&mut put, &batches);
        // Fail-closed: third batch never sent, first counted.
        assert_eq!(calls, 2);
        assert_eq!(summary.completed_batches, 1);
        assert_eq!(summary.completed_ops, 1);
        assert!(summary.error.unwrap().contains("bad sequence"));
    }

    #[test]
    fn test_execute_uploads_transport_error_aborts() {
        use proton_api::SyncBatchRequest;
        let batches = vec![SyncBatchRequest::delete_batch("m", &["a".to_string()])];
        let mut put = |_: &SyncBatchRequest| -> Result<proton_api::SyncBatchResponse, String> {
            Err("network down".into())
        };
        let summary = execute_uploads(&mut put, &batches);
        assert_eq!(summary.completed_batches, 0);
        assert_eq!(summary.error.as_deref(), Some("network down"));
    }

    #[test]
    fn test_inventory_item_json_contract() {
        // Shim↔engine contract: stable keys, optional proton_id.
        let item = local("n1", Some("e1"), false, true, Some(100));
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["mkcal_uid"], "n1");
        assert_eq!(v["proton_id"], "e1");
        let back: LocalItem = serde_json::from_value(v).unwrap();
        assert_eq!(back, item);
    }
}
