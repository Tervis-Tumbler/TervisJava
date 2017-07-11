function Install-TervisJava7DeploymentRuleSet {
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
        Copy-Item -Path $JavaDeploymentRuleSetSourcePath -Destination $JavaDeploymentPath -Force
        Copy-Item -Path $JavaCertificateSourcePath -Destination $JavaDeploymentPath -Force

        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Import-Certificate -FilePath $Using:JavaDeploymentPath\TervisTumbler.cer -CertStoreLocation 'Cert:\LocalMachine\Root'        
            if (Test-Path -Path "C:\Program Files\Java\jre7\bin\keytool.exe") {
                . "C:\Program Files\Java\jre7\bin\keytool.exe" -importcert -file $Using:JavaDeploymentPath\TervisTumbler.cer -alias tervisselfsigned -keystore 'C:\Program Files (x86)\Java\jre7\lib\security\cacerts' -storepass $Using:JavaKeystoreCredential -noprompt
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
