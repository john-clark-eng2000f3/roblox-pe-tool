from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SectionDelta:
    name: str
    status: str  # 'modified', 'added', 'removed', 'unchanged'
    old_raw_size: int = 0
    new_raw_size: int = 0
    old_virtual_size: int = 0
    new_virtual_size: int = 0
    raw_size_diff: int = 0
    virtual_size_diff: int = 0
    old_entropy: float = 0.0
    new_entropy: float = 0.0
    entropy_diff: float = 0.0
    old_md5: Optional[str] = None
    new_md5: Optional[str] = None


@dataclass
class PeDiffResult:
    old_path: str
    new_path: str
    timestamp_delta_seconds: int
    old_timestamp_str: str
    new_timestamp_str: str
    section_deltas: List[SectionDelta] = field(default_factory=list)
    matched_signatures_delta: Dict[str, Any] = field(default_factory=dict)
    size_diff: int = 0
    growth_percentage: float = 0.0


def diff_pe_info(old_meta: Dict[str, Any], new_meta: Dict[str, Any]) -> PeDiffResult:
    """Compute delta between two PE metadata dictionaries produced by PeReader."""
    old_ts = old_meta.get("timestamp", 0)
    new_ts = new_meta.get("timestamp", 0)
    ts_diff = new_ts - old_ts

    old_ts_str = datetime.fromtimestamp(old_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if old_ts else "unknown"
    new_ts_str = datetime.fromtimestamp(new_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if new_ts else "unknown"

    old_sections = {s["name"]: s for s in old_meta.get("sections", [])}
    new_sections = {s["name"]: s for s in new_meta.get("sections", [])}

    # Preserve order of appearance across both binaries
    all_names = list(dict.fromkeys(list(old_sections.keys()) + list(new_sections.keys())))
    section_deltas: List[SectionDelta] = []

    for name in all_names:
        old_s = old_sections.get(name)
        new_s = new_sections.get(name)

        if old_s and not new_s:
            section_deltas.append(
                SectionDelta(
                    name=name,
                    status="removed",
                    old_raw_size=old_s.get("raw_size", 0),
                    old_virtual_size=old_s.get("virtual_size", 0),
                    raw_size_diff=-old_s.get("raw_size", 0),
                    virtual_size_diff=-old_s.get("virtual_size", 0),
                    old_entropy=old_s.get("entropy", 0.0),
                    old_md5=old_s.get("md5"),
                )
            )
        elif new_s and not old_s:
            section_deltas.append(
                SectionDelta(
                    name=name,
                    status="added",
                    new_raw_size=new_s.get("raw_size", 0),
                    new_virtual_size=new_s.get("virtual_size", 0),
                    raw_size_diff=new_s.get("raw_size", 0),
                    virtual_size_diff=new_s.get("virtual_size", 0),
                    new_entropy=new_s.get("entropy", 0.0),
                    new_md5=new_s.get("md5"),
                )
            )
        else:
            raw_diff = new_s["raw_size"] - old_s["raw_size"]
            v_diff = new_s["virtual_size"] - old_s["virtual_size"]
            ent_diff = round(new_s.get("entropy", 0.0) - old_s.get("entropy", 0.0), 4)

            same_hash = old_s.get("md5") and new_s.get("md5") and old_s.get("md5") == new_s.get("md5")
            if raw_diff == 0 and v_diff == 0 and same_hash:
                status = "unchanged"
            else:
                status = "modified"

            section_deltas.append(
                SectionDelta(
                    name=name,
                    status=status,
                    old_raw_size=old_s.get("raw_size", 0),
                    new_raw_size=new_s.get("raw_size", 0),
                    old_virtual_size=old_s.get("virtual_size", 0),
                    new_virtual_size=new_s.get("virtual_size", 0),
                    raw_size_diff=raw_diff,
                    virtual_size_diff=v_diff,
                    old_entropy=old_s.get("entropy", 0.0),
                    new_entropy=new_s.get("entropy", 0.0),
                    entropy_diff=ent_diff,
                    old_md5=old_s.get("md5"),
                    new_md5=new_s.get("md5"),
                )
            )

    old_sigs = set(old_meta.get("signatures", []))
    new_sigs = set(new_meta.get("signatures", []))

    sig_delta = {
        "added": sorted(list(new_sigs - old_sigs)),
        "removed": sorted(list(old_sigs - new_sigs)),
        "common": sorted(list(old_sigs & new_sigs)),
    }

    old_size = old_meta.get("file_size", 0)
    new_size = new_meta.get("file_size", 0)
    file_size_diff = new_size - old_size
    growth = (file_size_diff / old_size * 100.0) if old_size > 0 else 0.0

    return PeDiffResult(
        old_path=old_meta.get("file_path", "old"),
        new_path=new_meta.get("file_path", "new"),
        timestamp_delta_seconds=ts_diff,
        old_timestamp_str=old_ts_str,
        new_timestamp_str=new_ts_str,
        section_deltas=section_deltas,
        matched_signatures_delta=sig_delta,
        size_diff=file_size_diff,
        growth_percentage=round(growth, 2),
    )
