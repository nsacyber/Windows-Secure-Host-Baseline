#requires -Version 3
Set-StrictMode -Version 3

#todo: turn into functions

#todo: removed hardcoded path
$basePath = "$env:USERPROFILE\Documents\GitHub\Secure-Host-Baseline"

$policy = [pscustomobject]@{
    'PolicyName' = 'Adobe Reader'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
}

$policyPath = "$basePath\Adobe Reader\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'AppLocker'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit');
    'PolicyTemplatePath' = '.\..\..\..\..\Windows\';
}

$policyPath = "$basePath\AppLocker\Group Policy Objects\Computer\Audit"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'AppLocker'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Enforced');
    'PolicyTemplatePath' = '.\..\..\..\..\Windows\';
}

$policyPath = "$basePath\AppLocker\Group Policy Objects\Computer\Enforced"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'BitLocker'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows\';
}

$policyPath = "$basePath\BitLocker\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Chrome'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\'
}

$policyPath = "$basePath\Chrome\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'EMET'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\'
}

$policyPath = "$basePath\EMET\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Internet Explorer'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
}

$policyPath = "$basePath\Internet Explorer\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Internet Explorer'
    'PolicyScopes' = [string[]]@('User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
}

$policyPath = "$basePath\Internet Explorer\Group Policy Objects\User"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Office'
    'PolicyScopes' = [string[]]@('Computer','User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\';
}

$policyPath = "$basePath\Office\Group Policy Objects"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
}

$policyPath = "$basePath\Windows\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows'
    'PolicyScopes' = [string[]]@('User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
}

$policyPath = "$basePath\Windows\Group Policy Objects\User"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows Firewall'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
}

$policyPath = "$basePath\Windows Firewall\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


