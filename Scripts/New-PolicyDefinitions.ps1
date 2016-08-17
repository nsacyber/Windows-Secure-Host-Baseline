#requires -Version 3
Set-StrictMode -Version 3

#todo: turn into functions

#todo: removed hardcoded path
$basePath = "$env:USERPROFILE\Documents\GitHub\Secure-Host-Baseline"

#the OS version the OS Group Policy templates are for
$osVersion = '10.0.10586.0'

Set-Location -Path $basePath

$policy = [pscustomobject]@{
    'PolicyName' = 'Adobe Reader';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '15.17.0.0';
}

$policyPath = "$basePath\Adobe Reader\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'AppLocker';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit');
    'PolicyTemplatePath' = '.\..\..\..\..\Windows\';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\AppLocker\Group Policy Objects\Computer\Audit"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'AppLocker';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Enforced');
    'PolicyTemplatePath' = '.\..\..\..\..\Windows\';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\AppLocker\Group Policy Objects\Computer\Enforced"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'BitLocker';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows\';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\BitLocker\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force

$policy = [pscustomobject]@{
    'PolicyName' = 'Certificates'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain', 'Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Certificates\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force

$policy = [pscustomobject]@{
    'PolicyName' = 'Chrome';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '52.0.2743.116';
}

$policyPath = "$basePath\Chrome\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'EMET';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '5.51.0.0';
}

$policyPath = "$basePath\EMET\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Internet Explorer';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Internet Explorer\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Internet Explorer'
    'PolicyScopes' = [string[]]@('User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Internet Explorer\Group Policy Objects\User"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Office 2013'
    'PolicyScopes' = [string[]]@('Computer','User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '15.0.0.0';
}

$policyPath = "$basePath\Office\Group Policy Objects\Office 2013"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Windows\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows'
    'PolicyScopes' = [string[]]@('User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Windows\Group Policy Objects\User"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


$policy = [pscustomobject]@{
    'PolicyName' = 'Windows Firewall'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\..\Windows';
    'PolicyTemplateType' = 'OS';
    'PolicyTemplateVersion' = $osVersion;
}

$policyPath = "$basePath\Windows Firewall\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force


