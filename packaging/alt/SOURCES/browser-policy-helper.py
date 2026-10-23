#!/usr/bin/python3 -I
"""Load only the RPM-owned, stdlib-only privileged helper package."""
import sys

sys.path.insert(0, '/usr/lib/endpoint-agent/policy-helper')
from pc_agent.platform.linux.browser_policy_helper import main

raise SystemExit(main())
