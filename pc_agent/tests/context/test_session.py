from __future__ import annotations

from pc_agent.context_profiles.session import collect_session
from pc_agent.tests.context.conftest import FIXED_TIME


class InteractiveProbe:
    def session_info(self) -> dict[str, object]:
        return {"current_user_login": "operator", "interactive_session_present": True}


def test_session_profile_keeps_only_the_interactive_login() -> None:
    result = collect_session(InteractiveProbe(), collected_at=FIXED_TIME)

    assert result.sections.current_user_login == "operator"
    assert result.sections.interactive_session_present is True
    assert result.warnings == []
