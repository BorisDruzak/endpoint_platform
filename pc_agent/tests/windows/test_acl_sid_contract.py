"""Windows ACL SID comparisons must not depend on localized account labels."""

from __future__ import annotations


def test_localized_administrators_sid_is_accepted_but_user_sid_is_rejected() -> None:
    """Display-name comparison breaks protected-file provisioning on localized Windows."""
    from pc_agent.platform.windows.acl import _allowed_sid_strings, _expected_sid_strings

    class _Dacl:
        def __init__(self, sids):
            self._sids = sids

        def GetAceCount(self):
            return len(self._sids)

        def GetAce(self, index):
            return ((0, 0), 0, self._sids[index])

    class _Security:
        ACCESS_ALLOWED_ACE_TYPE = 0

        @staticmethod
        def ConvertSidToStringSid(sid):
            return sid

        @staticmethod
        def LookupAccountName(_system, principal):
            return ({
                "NT SERVICE\\EndpointAgent": "S-1-5-80-100",
                "NT SERVICE\\EndpointAgentUpdater": "S-1-5-80-101",
            }[principal], None, None)

    security = _Security()
    expected = _expected_sid_strings(security)
    localized_allowed = _allowed_sid_strings(
        _Dacl(["S-1-5-18", "S-1-5-32-544", "S-1-5-80-100", "S-1-5-80-101"]),
        security,
    )

    assert localized_allowed == expected
    assert _allowed_sid_strings(_Dacl(["S-1-5-32-545"]), security).issubset(expected) is False
