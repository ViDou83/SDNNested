# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
<#
.SYNOPSIS 

.EXAMPLE

.EXAMPLE

.EXAMPLE

.NOTES

#>
import-module .\SDNExpress\SDNExpressModule.psm1 -force
import-module .\utils\SDNNested-Module.psm1 -force

#Get credentials for provisionning
$DomainJoinCredential = GetCred $ConfigData.DomainJoinSecurePassword $DomainJoinCredential `
    "Enter Domain Admin Creds." $configdata.DomainJoinUserName
$LocalAdminCredential = GetCred $ConfigData.LocalAdminSecurePassword $LocalAdminCredential `
    "Enter the password for the local administrator of the SDN Hosts.  Username is ignored." "Administrator"

#Enable  Enhanced more everywhere
Set-VMHost -EnableEnhancedSessionMode $true

#Fixing Cred issue 
$Nodes = (Get-VM *SDN-HOST*).Name

foreach ( $node in $Nodes) {

    icm -VMNAme $node -Credential $DomainJoinCredential {
        $cred = $args[0]
        $DomainCred = $args[1]
        #Enable  Enhanced more everywhere
        Set-VMHost -EnableEnhancedSessionMode $true

        $RestName = (Get-ItemProperty "hklm:\system\currentcontrolset\services\nchostagent\parameters" -Name PeerCertificateCName).PeerCertificateCName
        Write-Host -ForegroundColor Yellow "Allowing WinRM with certificate authentication between $env:COMPUTERNAME and $RestName"

        Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
        $NCthumbprint = (Get-ChildItem Cert:\LocalMachine\root | ? { $_.Subject -match $RestName }).Thumbprint
        New-Item -Path WSMan:\localhost\ClientCertificate -URI * -Issuer $NCthumbprint -Credential $cred -force
        $Mythumbprint = (Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -match $env:COMPUTERNAME }).Thumbprint
        New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS -CertificateThumbPrint $Mythumbprint -force

        #Restart and fixing NcHostAgent,SblHostAgent, SBLMux service issue
        Get-Service  NcHostAgent,SlbHostAgent | Restart-Service -Force
        Get-VM *MUX* | %{
            icm -VMName $_.Name -Credential $DomainCred {
                Get-Service  SLBMux | Restart-Service -Force
            }
        }

        #Adding all VMs to cluster 
        Get-VM | Add-ClusterVirtualMachineRole

    } -ArgumentList $LocalAdminCredential, $DomainJoinCredential
    
}