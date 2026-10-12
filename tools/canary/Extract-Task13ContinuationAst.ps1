param([string]$Source,[string]$Output)
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'parse failure'}
$rows=@($ast.FindAll({param($n)
 if($n -is [Management.Automation.Language.InvokeMemberExpressionAst]){return $n.Expression.Extent.Text -match '^(\$(native|script:native|msi|db|view|record|hive|key|acl)|\[(Microsoft.Win32.RegistryKey|Runtime.InteropServices.Marshal|IO.File)\])$' -or $n.Member.Extent.Text -eq 'Translate'}
 if($n -is [Management.Automation.Language.CommandAst]){return $n.GetCommandName() -in @('Get-CimInstance','sc.exe','Get-AuthenticodeSignature') -or ($n.GetCommandName() -eq 'New-Object' -and $n.Extent.Text -match 'WindowsInstaller.Installer')}
 return $false
},$true)|ForEach-Object{@{start=$_.Extent.StartOffset;end=$_.Extent.EndOffset;name=$(if($_ -is [Management.Automation.Language.CommandAst]){$_.GetCommandName()}else{$_.Member.Extent.Text});expression=$_.Extent.Text}})
ConvertTo-Json -InputObject $rows -Depth 4|Set-Content -LiteralPath $Output -Encoding UTF8
