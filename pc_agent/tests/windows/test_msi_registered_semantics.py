"""Read database semantics without executing any MSI action or installing products."""
import os
from pathlib import Path
import subprocess
import pytest
from pc_agent.platform.windows.msi_inventory import NativeMsi, ProvenanceConflict


@pytest.mark.skipif(os.name!='nt',reason='native read-only MSI database API')
def test_registered_semantics_covers_binary_content_custom_action_targets_and_keys(tmp_path):
    script=tmp_path/'databases.ps1'
    script.write_text(r'''param($Directory)
$ErrorActionPreference='Stop'
$installer=New-Object -ComObject WindowsInstaller.Installer
foreach($label in @('original','same','binary-change','target-change','key-change')){
 $path=Join-Path $Directory ($label+'.msi');$db=$installer.OpenDatabase($path,3)
 $keys=$(if($label -eq 'key-change'){'`Action`, `Source`'}else{'`Action`'})
 $view=$db.OpenView('CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Source` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Target` CHAR(255) PRIMARY KEY '+$keys+')');$view.Execute();$view.Close()
 $view=$db.OpenView('CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)');$view.Execute();$view.Close()
 $order=$(if($label -eq 'same'){@('Two','One')}else{@('One','Two')})
 foreach($name in $order){
  $target=$(if($label -eq 'target-change'){'ChangedTarget'}else{'SafeTarget'})
  $view=$db.OpenView("INSERT INTO ``CustomAction`` (``Action``,``Type``,``Source``,``Target``) VALUES ('$name',1,'Probe','$target')");$view.Execute();$view.Close()
 }
 $payload=Join-Path $Directory ($label+'.bin');[IO.File]::WriteAllBytes($payload,[byte[]]$(if($label -eq 'binary-change'){@(0,255,9,0,13)}else{@(0,255,8,0,13)}))
 $record=$installer.CreateRecord(2);$record.StringData(1)='Probe';$record.SetStream(2,$payload)
 $view=$db.OpenView('INSERT INTO `Binary` (`Name`,`Data`) VALUES (?,?)');$view.Execute($record);$view.Close();$db.Commit()
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
}
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(tmp_path)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    native=NativeMsi()
    original=native.database_semantics(tmp_path/'original.msi')
    assert original==native.database_semantics(tmp_path/'same.msi')
    assert original['Binary']!=native.database_semantics(tmp_path/'binary-change.msi')['Binary']
    assert original['CustomAction']!=native.database_semantics(tmp_path/'target-change.msi')['CustomAction']
    assert original['CustomAction']!=native.database_semantics(tmp_path/'key-change.msi')['CustomAction']


@pytest.mark.skipif(os.name!='nt',reason='native read-only MSI database API')
@pytest.mark.parametrize('kind',['repeated-text','aggregate-binary','aggregate-rows'])
def test_semantics_enforces_database_wide_budgets(tmp_path,monkeypatch,kind):
    from pc_agent.platform.windows import msi_inventory
    script=tmp_path/'budget.ps1'
    script.write_text(r'''param($Directory)
$ErrorActionPreference='Stop'
$installer=New-Object -ComObject WindowsInstaller.Installer
$db=$installer.OpenDatabase((Join-Path $Directory 'budget.msi'),3)
$view=$db.OpenView('CREATE TABLE `Text` (`Id` SHORT NOT NULL, `Value` CHAR(0) PRIMARY KEY `Id`)');$view.Execute();$view.Close()
$value='RepeatedStringPoolValue'*100
foreach($id in 1..8){
 $view=$db.OpenView("INSERT INTO ``Text`` (``Id``,``Value``) VALUES ($id,'$value')");$view.Execute();$view.Close()
}
foreach($table in @('BinaryOne','BinaryTwo')){
 $view=$db.OpenView('CREATE TABLE `'+$table+'` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)');$view.Execute();$view.Close()
 $payload=Join-Path $Directory ($table+'.bin');[IO.File]::WriteAllBytes($payload,(New-Object byte[] 4096))
 $record=$installer.CreateRecord(2);$record.StringData(1)='Probe';$record.SetStream(2,$payload)
 $view=$db.OpenView('INSERT INTO `'+$table+'` (`Name`,`Data`) VALUES (?,?)');$view.Execute($record);$view.Close()
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
}
$db.Commit()
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
''',encoding='utf-8')
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(script),str(tmp_path)],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    path=tmp_path/'budget.msi'
    assert NativeMsi().database_semantics(path)
    if kind=='repeated-text':
        monkeypatch.setattr(msi_inventory,'MAX_SEMANTIC_TEXT_BYTES',5000,raising=False)
    elif kind=='aggregate-binary':
        monkeypatch.setattr(msi_inventory,'MAX_SEMANTIC_BINARY_BYTES',7000,raising=False)
    else:
        monkeypatch.setattr(msi_inventory,'MAX_SEMANTIC_ROWS',10,raising=False)
    with pytest.raises(ProvenanceConflict):NativeMsi().database_semantics(path)
