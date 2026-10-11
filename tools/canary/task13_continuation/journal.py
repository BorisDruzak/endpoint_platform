"""Complete chronological protected workload journal validation."""
from .codec import parse_json, require, integer, instant, digest


def validate_journal(raw, identity):
    require(type(raw) is bytes and 0 < len(raw) <= 33554432 and raw.endswith(b"\n"), "complete bounded journal")
    rows = [parse_json(line) for line in raw.splitlines()]
    require(len(rows) >= 5, "journal missing phases")
    last_ms, last_utc = 0, None
    required = [("ENTER", "WRAPPER"), ("RETURN", "WATCHDOG_ARMED"),
                ("ENTER", "SCRIPTBLOCK.INVOKE"), ("RETURN", "SCRIPTBLOCK.INVOKE"),
                ("RETURN", "WRAPPER")]
    cursor = 0
    for seq, row in enumerate(rows, 1):
        require(set(row) == {"utc", "ms", "run", "pid", "birth", "phase", "stage", "seq", "counts"},
                "journal exact schema")
        require(all(row[k] == v and type(row[k]) is type(v) for k, v in identity.items()), "journal identity")
        require(type(row["seq"]) is int and row["seq"] == seq, "journal sequence")
        ms, utc = integer(row["ms"], 0, 120000), instant(row["utc"])
        require(ms >= last_ms and (last_utc is None or utc >= last_utc), "journal rollback")
        require(row["phase"] in ("ENTER", "RETURN") and type(row["stage"]) is str, "journal incomplete operation")
        if row["stage"].startswith("PROFILE."):
            counts = row["counts"]
            require(type(counts) is dict and counts["started"] == counts["returned"]
                    and integer(counts["started"], 1) > 0, "unreturned native operation")
        if cursor < len(required) and (row["phase"], row["stage"]) == required[cursor]:
            cursor += 1
        last_ms, last_utc = ms, utc
    require(cursor == len(required) and (rows[-1]["phase"], rows[-1]["stage"]) == required[-1], "journal no complete finish")
    return {"rows": len(rows), "duration_ms": last_ms, "identity": identity, "rows_sha256": digest({"rows": rows})}
