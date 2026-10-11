"""Public entry is deliberately nonoperational; use the reviewed private bootstrap."""
import json

if __name__ == "__main__":
    print(json.dumps({"status":"NONOPERATIONAL","reason":"prepare and independently review the exact private bundle"}))
    raise SystemExit(2)
