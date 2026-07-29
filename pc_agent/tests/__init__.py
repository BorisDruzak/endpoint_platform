"""Agent test package namespace.

Keeping this namespace explicit prevents `pc_agent/tests/context` from
colliding with the server's independent `tests/context` package when both
foundation suites are collected in one pytest invocation.
"""
