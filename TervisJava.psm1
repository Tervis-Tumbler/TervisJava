function Install-TervisJavaDeploymentRuleSet {
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

        $JavaHomeDirectory = Get-JavaHomeDirectory -ComputerName $ComputerName

        if ($JavaHomeDirectory) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $CertPath = (Join-Path $Using:JavaDeploymentPath TervisTumbler.cer)
                $KeyToolPath = "$using:JavaHomeDirectory\bin\keytool.exe"
                $KeyStorePath = "$using:JavaHomeDirectory\lib\security\cacerts"
                Import-Certificate -FilePath $CertPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null    
                if (Test-Path -Path $using:JavaHomeDirectory\bin\keytool.exe) {
                    . "$KeytoolPath" -importcert -file $CertPath -alias tervisselfsigned -keystore $KeyStorePath -storepass $Using:JavaKeystoreCredential -noprompt # | Out-Null
                } else {
                    throw "Keytool.exe not found in $using:JavaHomeDirectory\bin\ on $using:ComputerName"
                }
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

function Set-JavaHomeEnvironmentVariable {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        $JavaHomeDirectory = Get-JavaHomeDirectory -ComputerName $ComputerName
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            [Environment]::SetEnvironmentVariable("JAVA_HOME", $using:JavaHomeDirectory, "Machine")
        }
    }
}

function Disable-JavaUpdate {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $Java32UpdateRegistryKeyPath = "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy\jucheck"
        $Java64UpdateRegistryKeyPath = "HKLM:\SOFTWARE\JavaSoft\Java Update\Policy\jucheck"
        $WoW6432RunRegistryKeyPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    }
    process {
        Write-Verbose "Disabling automatic Java updates on $ComputerName"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $ErrorActionPreference = "SilentlyContinue"
            New-Item -Name JavaSoft -Path HKLM:\SOFTWARE\WOW6432Node 
            New-Item -Name "Java Update" -Path HKLM:\SOFTWARE\WOW6432Node\JavaSoft
            New-Item -Name Policy -Path "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update"
            New-Item -Name jucheck -Path 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Update\Policy'
            New-ItemProperty -Path $Using:Java32UpdateRegistryKeyPath -Name EnableAutoUpdateCheck -PropertyType DWORD -Value 0
            New-Item -Name JavaSoft -Path HKLM:\SOFTWARE\
            New-Item -Name "Java Update" -Path HKLM:\SOFTWARE\JavaSoft
            New-Item -Name Policy -Path "HKLM:\SOFTWARE\JavaSoft\Java Update"
            New-Item -Name jucheck -Path 'HKLM:\SOFTWARE\JavaSoft\Java Update\Policy'
            New-ItemProperty -Path $Using:Java64UpdateRegistryKeyPath -Name EnableAutoUpdateCheck -PropertyType DWORD -Value 0
            Remove-ItemProperty -Path $Using:WoW6432RunRegistryKeyPath -Name SunJavaUpdateSched
            $ErrorActionPreference = "Continue"
        }
    }
}

function Get-JavaHomeDirectory {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $JavaRootDir32 = "C:\Program Files (x86)\Java"
        $JavaRootDir64 = "C:\Program Files\Java"
    }
    process {
        $JavaRootDir32Remote = $JavaRootDir32 | ConvertTo-RemotePath -ComputerName $ComputerName
        $JavaRootDir64Remote = $JavaRootDir64 | ConvertTo-RemotePath -ComputerName $ComputerName
        $JavaExecutables32 = Get-ChildItem -Path $JavaRootDir32Remote\j*\bin\Java.exe -ErrorAction SilentlyContinue
        $JavaExecutables64 = Get-ChildItem -Path $JavaRootDir64Remote\j*\bin\Java.exe -ErrorAction SilentlyContinue

        if ($JavaExecutables32) {
            return $JavaExecutables32 | 
                sort {$_.VersionInfo.FileVersion} | 
                select -Last 1 -ExpandProperty Directory | 
                Split-Path -Parent | 
                ConvertFrom-RemotePath
        } elseif ($JavaExecutables64) {
            return $JavaExecutables64 | 
                sort {$_.VersionInfo.FileVersion} | 
                select -Last 1 -ExpandProperty Directory | 
                Split-Path -Parent | 
                ConvertFrom-RemotePath
        } else {
            Write-Warning "No Java home directory found on $ComputerName."
        }
    }
}
