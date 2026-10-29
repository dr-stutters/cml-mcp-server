"""Back-out steps for the write tools (core C81 `Plan.undo`).

Each write's Plan names how to reverse it: an `Undo(tool, args)` for the call that puts things back (the
preview shows it as 'back-out: ...', the applied result and the audit log carry it), or a text when no call
can (a wipe, a delete, a console change). An undo is a preview-first call like any other write.

The core masks secret-looking values in the undo arguments it shows and returns (an enable secret in a
config, a password argument). Replaying a masked value would write '********' to the device, so a previous
value that does not survive the masking is never offered as a call: the step says where to get it instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cml_mcp._core import FromResult, Undo
from cml_mcp._core.audit import redact_args

# How a deleted or wiped lab comes back: only from an archive taken before (CML has no recycle bin).
ARCHIVE_FIRST = (
    "archive first (cml_archive_lab); a lab comes back with cml_import_lab of the archive's topology.yaml"
)

# cml_set_link_condition arguments for the netem fields CML returns on GET .../condition
CONDITION_ARGS = {
    "latency": "latency_ms",
    "jitter": "jitter_ms",
    "loss": "loss_pct",
    "bandwidth": "bandwidth_kbps",
    "duplicate": "duplicate_pct",
    "corrupt_prob": "corrupt_pct",
}


def not_reversible(why: str) -> str:
    return f"not reversible: {why}"


def replayable(tool: str, args: Mapping[str, Any]) -> bool:
    """True when `args` come back from the core's masking unchanged, so the undo can be replayed as shown."""
    plain = dict(args)
    return redact_args(plain, tool=tool, max_chars=None) == plain


def condition_undo(lab_id: str, link_id: str, current: Mapping[str, Any]) -> Undo:
    """Put a link's conditioning back as it was: its previous netem values, or none at all."""
    values = {
        arg: current[field]
        for field, arg in CONDITION_ARGS.items()
        if current.get(field) not in (None, 0, 0.0)
    }
    if current.get("enabled") and values:
        return Undo("cml_set_link_condition", {"lab": lab_id, "link": link_id, **values})
    return Undo("cml_clear_link_scenarios", {"lab": lab_id, "link": link_id})


def delete_new_lab(*, force: bool = False) -> Undo:
    """The undo of anything that creates a lab: delete it by the id in the apply result."""
    return Undo("cml_delete_lab", {"lab": FromResult("id"), **({"force": True} if force else {})})


def cli_back_out(label: str, mode: str, save: bool) -> str:
    """The back-out text of a console change: there is no recorded 'before' to push back."""
    if mode == "exec":
        return not_reversible(
            f"exec lines run once on {label}; run the device's own reverse command with cml_configure_node "
            "(e.g. FTD 'configure manager delete' after 'configure manager add')"
        )
    saved = (
        " The change was saved (write memory): the old startup config is gone unless an archive "
        "(cml_archive_lab) or cml_extract_node_configs kept it."
        if save
        else " Not saved: a node restart without saving (cml_set_node_state stop/start) also drops it."
    )
    return (
        f"push the negation with cml_configure_node on {label}: 'no <line>' for each line in reverse order "
        "(drop the 'no' of a 'no ...' line; re-enter the parent such as 'interface ...' first). "
        "cml_diff_node_config(against='day0') shows what differs from the day-0." + saved
    )
