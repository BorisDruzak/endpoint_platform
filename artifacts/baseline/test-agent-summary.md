# Test-agent baseline summary

- Source commit: `8be364000089d70bac3ccf9aaef4f84397ca21a7`
- Generated at: `2026-07-28T13:14:39.514626+00:00`
- Platform: ALT Workstation K 11.4

## Command results

1. Retained agent suite excluding manual tests: exit `2`.
   - Collection errors: `pc_agent/tests/test_remote_assist_runtime_module_package.py` requires excluded `scripts.build_module_zip`.
   - Collection errors: `pc_agent/tests/test_support_module_packages.py` requires excluded `scripts.register_support_modules`.
2. Update and launcher characterization suite: exit `1`.
   - Passed: `32`.
   - Failed: `pc_agent/tests/test_self_update_runtime.py::test_apply_update_prunes_old_version_directories_after_success`.
3. `compileall` for `pc_agent` and `shared`: exit `0`.

Overall exit code: `1`

This is a baseline record, not an agent behavior change. The missing `scripts` imports and the update-test failure remain source-characterization findings for the next extraction task.
