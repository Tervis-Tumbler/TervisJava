﻿function Install-TervisJava7DeploymentRuleSet {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $JavaKeystoreCredential = (Get-PasswordstateCredential -PasswordID 4282).GetNetworkCredential().Password
        $JavaDeploymentPath = "C:\Windows\Sun\Java\Deployment"
        $JavaDeploymentRuleSetSourcePath = "\\$env:USERDNSDOMAIN\applications\PowerShell\JavaCerts\DeploymentRuleSet.Jar"
        $JavaCertificateSourcePath = "\\$env:USERDNSDOMAIN\applications\PowerShell\JavaCerts\TervisTumbler.cer"
    }
    process {
        $JavaDeploymentRemotePath = $JavaDeploymentPath | ConvertTo-RemotePath -ComputerName $ComputerName            
        if (-not (Test-Path -Path $JavaDeploymentRemotePath)) {
            New-Item -Type Directory -Path $JavaDeploymentRemotePath | Out-Null
        }
        Copy-Item -Path $JavaDeploymentRuleSetSourcePath -Destination $JavaDeploymentRemotePath -Force
        Copy-Item -Path $JavaCertificateSourcePath -Destination $JavaDeploymentRemotePath -Force

        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $CertPath = (Join-Path $Using:JavaDeploymentPath TervisTumbler.cer)
            Import-Certificate -FilePath $CertPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null    
            if (Test-Path -Path "C:\Program Files\Java\jre7\bin\keytool.exe") {
                . "C:\Program Files\Java\jre7\bin\keytool.exe" -importcert -file $CertPath -alias tervisselfsigned -keystore 'C:\Program Files (x86)\Java\jre7\lib\security\cacerts' -storepass $Using:JavaKeystoreCredential -noprompt | Out-Null
            } else {
                throw "Keytool.exe not found in C:\Program Files\Java\jre7\bin"
            }
        }
    }
}

function Set-JavaToolOptionsEnvironmentVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            [Environment]::SetEnvironmentVariable( "JAVA_TOOL_OPTIONS", '-Djava.vendor="Sun Microsystems Inc."', "Machine" )
        }
    }
}

function Disable-JavaUpdate {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $JavaUpdateRegistryKeyPath = "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy\jucheck"
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Name JavaSoft -Path HKLM:\SOFTWARE\WOW6432Node
            New-Item -Name "Java Update" -Path HKLM:\SOFTWARE\WOW6432Node\JavaSoft
            New-Item -Name Policy -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update"
            New-Item -Name jucheck -Path 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy'
            New-ItemProperty -Path $Using:JavaUpdateRegistryKeyPath -Name EnableAutoUpdateCheck -PropertyType DWORD -Value 0
        } | Out-Null
    }
}
