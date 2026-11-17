"""The observer must hash native Python journals without changing their JSON values."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/windows/EndpointSetupUpdater.ps1'
TRANSACTION = '22222222-2222-4222-8222-222222222222'


def owner(pid=1234):
    return dict(pid=pid, created=134383746580000000, sid='S-1-5-18', elevated=True, hash='9' * 64)


def completion(helper_count):
    # Shape produced by installer_transaction_bridge._public_fence/_advance_fence.
    return dict(schema_version=1, transaction_id=TRANSACTION, phase='complete', operation='install',
        package=dict(sha256='a' * 64, product_code='{11111111-1111-4111-8111-111111111111}',
            package_code='{33333333-3333-4333-8333-333333333333}', version='3.2.169', source_revision='b' * 40),
        selected='c' * 64, previous=None,
        service_states=dict(EndpointAgent='running', EndpointAgentUpdater='stopped'),
        service_startup=dict(EndpointAgent=dict(start_type=2, delayed_auto=False), EndpointAgentUpdater=None),
        startup_restored=True, sequence=6,
        helpers=[dict(pid=1234 + index, creation_time=134383746580000000 + index,
            image_sha256='9' * 64, phase='complete', complete=True) for index in range(helper_count)])


def continuation_grant(helper_count):
    # Shape produced by native_setup_continuation.reserve_native_continuation.
    receipt = completion(helper_count)
    return dict(schema_version=1, transaction_id=TRANSACTION, package=receipt['package'], owner=owner(),
        helper_sha256='d' * 64, capture=dict(transaction_id=TRANSACTION, previous=None),
        selection=dict(selected_sha256='c' * 64, previous_sha256=None, tree_sha256='e' * 64),
        completion=receipt, before_fence_sha256='f' * 64,
        completion_relative=f'transactions/{TRANSACTION}/completed.json', native_fence_relative='native.json',
        native_session_id='44444444-4444-4444-8444-444444444444',
        native_capability_sha256='8' * 64, compound_plan_sha256=None)


CASES = [
    pytest.param(completion(count), id=f'completion-helpers-{count}') for count in (0, 1, 2)
] + [
    pytest.param(continuation_grant(count), id=f'grant-helpers-{count}') for count in (0, 1, 2)
] + [
    pytest.param(dict(nested=[[], ['one'], [['two']], [owner(), owner(1235)],
        [None, dict(helpers=[])]], previous=None, compound=None), id='nested-arrays'),
    pytest.param(dict(text='line\nnext'), id='newline'),
    pytest.param(dict(text='column\tnext'), id='tab'),
    pytest.param(dict(text='return\rnext'), id='carriage-return'),
    pytest.param(dict(text='back\bnext'), id='backspace'),
    pytest.param(dict(text='form\fnext'), id='form-feed'),
    pytest.param(dict(text='C:\\native\\"receipt"\x00\x1f'), id='quotes-backslashes-controls'),
    pytest.param(dict(text='Привет \U0001f6e0 \u007f'), id='unicode-surrogate-pair'),
]


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell5.1 canonical native journals')
@pytest.mark.parametrize('representation', ['pscustomobject', 'dictionary'])
@pytest.mark.parametrize('record', CASES)
def test_native_json_canonical_text_and_hash_match_python_oracle(tmp_path, record, representation):
    expected = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    source = tmp_path / 'native.json'
    source.write_text(expected, encoding='utf-8')
    output = tmp_path / 'actual.json'
    harness = tmp_path / 'canonical.ps1'
    harness.write_text(r'''
param($Script,$InputPath,$OutputPath,$Representation)
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Script,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'observer source parse failed'}
$functions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in @('ConvertTo-SetupCanonicalJson','Get-SetupCanonicalHash')},$true))
if($functions.Count -ne 2){throw 'canonical functions missing'}
foreach($function in $functions){Invoke-Expression $function.Extent.Text}
$value=[IO.File]::ReadAllText($InputPath,[Text.Encoding]::UTF8)|ConvertFrom-Json
if($Representation -ceq 'dictionary'){
 $dictionary=@{}
 foreach($property in $value.psobject.Properties){$dictionary[$property.Name]=$property.Value}
 $value=$dictionary
}
$actual=@{canonical=(ConvertTo-SetupCanonicalJson $value);sha256=(Get-SetupCanonicalHash $value)}
[IO.File]::WriteAllText($OutputPath,($actual|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
''', encoding='utf-8')
    # A child of PowerShell7 must discover Windows PowerShell5.1's own modules.
    environment = {key: value for key, value in os.environ.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(harness), str(SCRIPT),
        str(source), str(output), representation], capture_output=True, text=True, timeout=20, env=environment)
    assert result.returncode == 0, result.stdout + result.stderr
    actual = json.loads(output.read_text(encoding='utf-8'))
    assert (actual['canonical'], actual['sha256']) == (
        expected, hashlib.sha256(expected.encode('utf-8')).hexdigest())
