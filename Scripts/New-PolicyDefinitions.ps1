#requires -Version 3
Set-StrictMode -Version 3

# todo: turn into functions

# todo: removed hardcoded path
$basePath = "$env:USERPROFILE\Documents\GitHub\Secure-Host-Baseline"

# Windows 10 1607 OS Group Policy Templates 
# taken from https://www.microsoft.com/en-us/download/details.aspx?id=53430 (Version 2.0 released on 01/08/2017)
# Note that there are some differences between Version 2.0 and what is in the PolicyDefinitions folder on a Windows 10 Enterprise 1607 14393.693 system as of 01/18/2017
$osVersion = '10.0.14393.0'

Set-Location -Path $basePath

$policy = [pscustomobject]@{
    'PolicyName' = 'ActivClient';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '7.1.0.157';
}

$policyPath = "$basePath\ActivClient\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force

$policy = [pscustomobject]@{
    'PolicyName' = 'Adobe Reader';
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '15.23.0.0';
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
    'PolicyTemplateVersion' = '55.0.2883.87';
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
    'PolicyTemplatePath' = '.\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '15.0.0.0';
}

$policyPath = "$basePath\Office\Office 2013\Group Policy Objects"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force

$policy = [pscustomobject]@{
    'PolicyName' = 'Office 2016'
    'PolicyScopes' = [string[]]@('Computer');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '16.0.0.0';
}

$policyPath = "$basePath\Office\Office 2016\Group Policy Objects\Computer"
$policy | ConvertTo-Json | Out-File -FilePath "$policyPath\policy.json" -Encoding ASCII -Force

$policy = [pscustomobject]@{
    'PolicyName' = 'Office 2016'
    'PolicyScopes' = [string[]]@('User');
    'PolicyTypes' = [string[]]@('Domain','Local');
    'PolicyModes' = [string[]]@('Audit','Enforced');
    'PolicyTemplatePath' = '.\..\..\';
    'PolicyTemplateType' = 'Application';
    'PolicyTemplateVersion' = '16.0.0.0';
}

$policyPath = "$basePath\Office\Office 2016\Group Policy Objects\User"
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


