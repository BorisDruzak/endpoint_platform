"""Non-production rollback fixture; never register as an Agent release.

Its distinct version avoids changing immutable 3.2.80 bytes. The fixture passes
the offline worker's executable checks, then exits without opening a network
connection or producing a WSS startup proof. This deliberately simplified
verifier is fault injection, not evidence for production candidate verification.
"""

from __future__ import annotations

import sys
import time


FIXTURE_VERSION = "99.0.3280"


def main() -> int:
    if sys.argv[1:] == ["--print-version"]:
        print(FIXTURE_VERSION)
        return 0
    if "--verify" in sys.argv[1:]:
        return 0
    time.sleep(8)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
