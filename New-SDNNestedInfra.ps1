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
[CmdletBinding(DefaultParameterSetName = "NoParameters")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = ".\utils\SDNNested-Deploy-Infra.psd1"
)    

import-module .\SDNExpress\SDNExpressModule.psm1 -force
import-module .\utils\SDNNested-Module.psm1 -force

# Script version, should be matched with the config files
$ScriptVersion = "2.0"

#Validating passed in config files
if ($psCmdlet.ParameterSetName -eq "ConfigurationFile") {
    Write-Host "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
}
elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
    Write-Host "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
    Write-Host "Configuration file $ConfigurationDataFile version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express."
    Write-Host "Please update your config file to match the version $scriptversion example."
    return
}

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Checking and getting credentials"
Write-Host "####"
Write-Host "########"
Write-Host "############"

#Get credentials for provisionning
$DomainJoinCredential = GetCred $ConfigData.DomainJoinSecurePassword $DomainJoinCredential `
    "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
$LocalAdminCredential = GetCred $ConfigData.LocalAdminSecurePassword $LocalAdminCredential `
    "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

$DomainJoinPassword = $DomainJoinCredential.GetNetworkCredential().Password
$LocalAdminPassword = $LocalAdminCredential.GetNetworkCredential().Password

$DomainJoinUserNameDomain = $ConfigData.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $ConfigData.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $ConfigData.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $ConfigData.LocalAdminDomainUser.Split("\")[1]

$password = $LocalAdminPassword | ConvertTo-SecureString -asPlainText -Force
$LocalAdminCredential = New-Object System.Management.Automation.PSCredential(".\administrator", $password)

if ( $null -eq $ConfigData.VMProcessorCount) { $ConfigData.VMProcessorCount = 2 }
if ( $null -eq $ConfigData.VMMemory) { $ConfigData.VMMemory = 4GB }

Write-Host -ForegroundColor Green "Domain Admin Credantial=$DomainJoinUserNameName"
Write-Host -ForegroundColor Green "Local Admin Credantial=$LocalAdminDomainUserName"

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "#### This script will deploy Hyper-V hosts and DC to host SDN stack based on the configuration file passed in $ConfigurationDataFile"
Write-Host "#### Checking if all prerequisites before deploying"
Write-Host "####"
Write-Host "########"
Write-Host "############"
#Checking Hyper-V role
$HypvIsInstalled = Get-WindowsFeature Hyper-V
if ( $HypvIsInstalled.InstallState -eq "Installed" ) {
    Write-Host -ForegroundColor Green "Hypv role is $($HypvIsInstalled.installstate)"
}
else {
    throw "Hyper-V Feature needs to be installed in order to deploy SDN nested"    
}
#Checking VMSwitch
$vmswitch = get-vmswitch
if ( $null -eq $vmswitch ) {
    #throw "No virtual switch found on this host.  Please create the virtual switch before adding this host."
    $vmswitch = New-VMSwitch -Name $configdata.SwitchName -SwitchType Internal
}    

if ( $vmswitch.name | Where-Object { $_ -eq $configdata.SwitchName } ) { 
    Write-Host -ForegroundColor Green "VMSwitch $($configdata.SwitchName) found"
}
else {
    throw "No virtual switch $($configdata.SwitchName) found on this host.  Please create the virtual switch before adding this host."    
}

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Connecting $env:computername to the SDN switch"
Write-Host "####"
Write-Host "########"
Write-Host "############"
Connect-HostToSDN $configdata.HostSdnNICs $vmswitch.Name $configdata.PublicVIPNetRoute



<#
    SDN DC DEPLOYMENT
#>
Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "###  Start Domain controller deployment "
Write-Host "####"
Write-Host "########"
Write-Host "############"

#Checking if DCs are defined
if ( $null -eq $configdata.DCs ) {
    throw "No Domain Controller configuration defined."    
}

$paramsAD = @{
    'VMLocation'          = $ConfigData.VMLocation;
    'VMName'              = '';
    'VHDSrcPath'          = $ConfigData.VHDPath;
    'VHDName'             = '';
    'VMMemory'            = $ConfigData.VMMemory;
    'VMProcessorCount'    = $ConfigData.VMProcessorCount;
    'SwitchName'          = $ConfigData.SwitchName;
    'NICs'                = @();
    'CredentialDomain'    = $DomainJoinUserNameDomain;
    'CredentialUserName'  = $DomainJoinUserNameName;
    'CredentialPassword'  = $DomainJoinPassword;
    'JoinDomain'          = $ConfigData.DomainFQDN;
    'LocalAdminPassword'  = $LocalAdminPassword;
    'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
    'DomainAdminUserName' = $LocalAdminDomainUserName;
    'IpGwAddr'            = $ConfigData.ManagementGateway;
    'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
}

#Creating DC
foreach ( $dc in $configdata.DCs) 
{
    $paramsAD.VMName = $dc.ComputerName
    $paramsAD.Nics = $dc.NICs
    #Creating DC with Desktop env 
    $paramsAD.VHDName = $configdata.VHDGUIFile

    New-SdnNestedVm @paramsAD 

    Start-VM $dc.ComputerName

    WaitLocalVMisBooted $dc.computername $LocalAdminCredential
    if( $dc -eq $configdata.DCs[0])
    {
        New-SDNNestedADDSForest $dc.Computername $LocalAdminCredential $configdata.DomainFQDN
    }
    else
    {
        Add-SDNNestedADDSDomainController $dc.Computername $LocalAdminCredential $configdata.DomainFQDN
    }
    Write-Host  "Configuring VLAN VLANID=$($dc.NICs[0].VLANID) VM=$($dc.computername)"
    Get-VMNetworkAdapter -VMName $dc.computername | Set-VMNetworkAdapterVlan -Access -VlanId $dc.NICs[0].VLANID
}

WaitLocalVMisBooted $configdata.DCs[-1].computername $DomainJoinCredential

<#
    SDN HOST DEPLOYMENT
#>
Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Start Hypv hosts deployment "
Write-Host "####"
Write-Host "########"
Write-Host "############"

#Checking if DCs are defined
if ( $null -eq $configdata.HyperVHosts ) {
    throw "No Hyper-V Host configuration defined."    
}

$paramsHOST = @{
    'VMLocation'          = $ConfigData.VMLocation;
    'VMName'              = '';
    'VHDSrcPath'          = $ConfigData.VHDPath;
    'VHDName'             = $ConfigData.VHDFile;
    'VMMemory'            = '';
    'VMProcessorCount'    = '';
    'SwitchName'          = $ConfigData.SwitchName;
    'NICs'                = @();
    'CredentialDomain'    = $DomainJoinUserNameDomain;
    'CredentialUserName'  = $DomainJoinUserNameName;
    'CredentialPassword'  = $DomainJoinPassword;
    'JoinDomain'          = $ConfigData.DomainFQDN;
    'LocalAdminPassword'  = $LocalAdminPassword;
    'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
    'DomainAdminUserName' = $LocalAdminDomainUserName;
    'IpGwAddr'            = $ConfigData.ManagementGateway;
    'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
}

#Creating HYPV Hosts
foreach ( $node in $configdata.HyperVHosts) 
{
    $paramsHOST.VMName = $node.ComputerName
    $paramsHOST.Nics = $node.NICs
    $paramsHOST.VMMemory =  $node.VMMemory
    $paramsHOST.VMProcessorCount = 4

    New-SdnNestedVm @paramsHOST

    #required for nested virtualization 
    Get-VM -Name $node.ComputerName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
    #Required to allow multiple MAC per vNIC
    Get-VM -Name $node.ComputerName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On

    Write-Host -ForegroundColor Green "Adding  VM S2D DataDisk on $($node.ComputerName)" 
    Add-VMDataDisk $node.ComputerName $ConfigData.S2DDiskSize $ConfigData.S2DDiskNumber
 
    Start-VM $node.ComputerName 
     
    WaitLocalVMisBooted $node.ComputerName $DomainJoinCredential 

    $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"
    Add-WindowsFeatureOnVM $node.computername $DomainJoinCredential $FeatureList 
    
    Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential {
        Write-Host "Adding SDN VMSwitch on $($env:COMPUTERNAME)"
        New-VMSwitch -NetAdapterName $(Get-Netadapter).Name -SwitchName SDNSwitch -AllowManagementOS $true | Out-Null
        Get-VMNetworkAdapter -ManagementOS -Name SDNSwitch | Rename-VMNetworkAdapter -NewName MGMT
        Get-VMNetworkAdapter -ManagementOS -Name MGMT | Set-VMNetworkAdapterVlan -Access -VlanId $args[0]
        #Cred SSDP for remote administration
        Write-Host "Allowing CredSSP to manage HYPV host $($env:COMPUTERNAME) from Azure VM"
        Enable-WSManCredSSP -Role Server -Force | Out-Null
        Set-VMHost  -EnableEnhancedSessionMode $true
    } -ArgumentList $Node.NICs[0].VLANID
    
    Get-VMNetworkAdapter -VMName $node.ComputerName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
    #Adding credential to the cache
    Invoke-Expression -Command `
        "cmdkey /add:$($node.ComputerName).$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null
}

WaitLocalVMisBooted $configdata.HyperVHosts[-1].Computername $DomainJoinCredential

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Configuring S2D Cluster "
Write-Host "####"
Write-Host "########"
Write-Host "############"
New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $DomainJoinCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName 

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Start  SDN stack Tenant GW deployment "
Write-Host "####"
Write-Host "########"
Write-Host "############"

$paramsGW = @{
    'VMLocation'          = $ConfigData.VMLocation;
    'VMName'              = '';
    'VHDSrcPath'          = $ConfigData.VHDPath;
    'VHDName'             = $ConfigData.VHDFile;
    'VMMemory'            = $ConfigData.VMMemory;
    'VMProcessorCount'    = $ConfigData.VMProcessorCount;
    'SwitchName'          = $ConfigData.SwitchName;
    'NICs'                = @();
    'CredentialDomain'    = $DomainJoinUserNameDomain;
    'CredentialUserName'  = $DomainJoinUserNameName;
    'CredentialPassword'  = $DomainJoinPassword;
    'JoinDomain'          = $ConfigData.DomainFQDN;
    'LocalAdminPassword'  = $LocalAdminPassword;
    'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
    'DomainAdminUserName' = $LocalAdminDomainUserName;
    'IpGwAddr'            = $ConfigData.ManagementGateway;
    'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
}


#Creating Gw Hosts
foreach ( $GW in $configdata.TenantInfraGWs) {
    $paramsGW.VMName = $GW.ComputerName
    $paramsGW.Nics = $GW.NICs

    New-SdnNestedVm @paramsGW 

    Start-VM $GW.ComputerName

    WaitLocalVMisBooted $GW.ComputerName $LocalAdminCredential

    foreach ( $TenantvGW in $configdata.TenantvGWs) {
        if ( $TenantvGW.Tenant -eq $GW.Tenant ) 
        {

            Add-WindowsFeatureOnVM $GW.ComputerName $LocalAdminCredential RemoteAccess
            <#
            invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential {
                $TenantvGW = $args[0]
                Write-Host -ForegroundColor Yellow "Checking IP config from $($TenantvGW.VirtualGwName) config"
            
                Write-Host -ForegroundColor Green "Adding Remote Access feature on $env:COMPUTERNAME"
                $res = Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools

                if ( $res.RestartNeeded -eq "Yes" ) { Restart-Computer -Force; Write-host "Rebooting $env:COMPUTERNAME" }
            } -ArgumentList $TenantvGW
            #>

            invoke-Command -VMName  $GW.ComputerName  -Credential $LocalAdminCredential {
                $TenantvGW = $args[0]

                $tunnelMode = $false                   
                if ( $TenantvGW.Type -eq "L3") {
                    $VpnType = "RoutingOnly"    
                }
                elseif ( $TenantvGW.Type -eq "GRE") {
                    $VpnType = "VpnS2S"   
                    $tunnelMode = $true                                    
                }
                Write-Host -ForegroundColor Green "Installing Remote Access VPNtype=$VpnType on $env:COMPUTERNAME"

                Install-RemoteAccess -VpnType $VpnType  
            
                $run = (Get-Service RemoteAccess).status

                if ( $run -ne "Running") { Start-Service RemoteAccess }

                if (  $tunnelMode ) {
                    Write-Host -ForegroundColor Yellow "Configuring $($TenantvGW.Type) tunnel on $env:COMPUTENAME"
                    if ( $TenantvGW.Type -eq "GRE") {
                        #GRE VIP POOL
                        if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $TenantvGW.GrePeer) ) { 
                            Write-Host -ForegroundColor Yellow "IP Address $($TenantvGW.GrePeer) is missing so adding it"
                            New-NetIPAddress -InterfaceIndex (Get-NetAdapter).ifIndex -IPAddress $TenantvGW.GrePeer -PrefixLength 32 | Out-Null
                        }
                        $GrepVIPPool = "2.2.2.2"
                        
                        Add-VpnS2SInterface -Name FabrikamGRE -Destination $GrepVIPPool -SourceIpAddress $TenantvGW.GrePeer -GreKey $TenantvGW.PSK `
                            -GreTunnel -IPv4Subnet "$($TenantvGW.RouteDstPrefix):10"
                    }
                }
                # 
                if ( $TenantvGW.BGPEnabled) {
                    if ( ! (Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $TenantvGW.BgpPeerIpAddress ) { 
                        Write-Host -ForegroundColor Yellow "IP Address $($TenantvGW.PeerIpAddrGW) is missing so adding it"
                        New-NetIPAddress -InterfaceIndex (Get-NetAdapter).ifIndex -IPAddress $TenantvGW.BgpPeerIpAddress -PrefixLength 24
                    }
                    
                    try {
                        $bgpRouter = Get-BgpRouter -ErrorAction Ignore
                    }
                    catch { }
                    
                    if ( ! $bgpRouter ) {
                        Add-BgpRouter -BgpIdentifier $TenantvGW.BgpPeerIpAddress -LocalASN $TenantvGW.BgpPeerAsNumber                        
                    }
                    
                    try {
                        $BpgPeer = Get-BgpPeer -Name $TenantvGW.VirtualGwName -ErrorAction Ignore
                    }
                    catch { }

                    if ( ! $BpgPeer ) {                 
                        Add-BgpPeer -Name $TenantvGW.VirtualGwName -LocalIPAddress $TenantvGW.BgpPeerIpAddress -LocalASN $TenantvGW.BgpPeerAsNumber `
                            -PeerIPAddress $TenantvGW.BgpLocalRouterIP[0] -PeerASN $($TenantvGW.BgpLocalExtAsNumber).split(".")[1] -OperationMode Mixed `
                            -PeeringMode Automatic
                    }   
                }
            } -ArgumentList $TenantvGW
        }     
    }
}

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### ToR Router deployement "
Write-Host "####"
Write-Host "########"
Write-Host "############"
#Creating ToR Router
foreach ( $ToR in $configdata.TORrouter) 
{

    $credential = $DomainJoinCredential

    if ( ! (get-vm $ToR.ComputerName -ErrorAction silentlycontinue ) ){
        $paramsToR = @{
            'VMLocation'          = $ConfigData.VMLocation;
            'VMName'              = $ToR.ComputerName;
            'VHDSrcPath'          = $ConfigData.VHDPath;
            'VHDName'             = $ConfigData.VHDFile;
            'VMMemory'            = $ConfigData.VMMemory;
            'VMProcessorCount'    = $ConfigData.VMProcessorCount;
            'SwitchName'          = $ConfigData.SwitchName;
            'NICs'                = $ToR.NICs;
            'CredentialDomain'    = $DomainJoinUserNameDomain;
            'CredentialUserName'  = $DomainJoinUserNameName;
            'CredentialPassword'  = $DomainJoinPassword;
            'JoinDomain'          = $ConfigData.DomainFQDN;
            'LocalAdminPassword'  = $LocalAdminPassword;
            'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
            'DomainAdminUserName' = $LocalAdminDomainUserName;
            'IpGwAddr'            = '';
            'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
            'DomainFQDN'          = $ConfigData.DomainFQDN;
            'ProductKey'          = $ConfigData.ProductKey;
        }

        New-SdnNestedVm @paramsToR

        $credential = $LocalAdminCredential
        Start-VM $ToR.ComputerName

        WaitLocalVMisBooted $ToR.ComputerName $credential
    }

    New-ToRrouter $configdata.TORrouter.ComputerName $credential $ToR

}


Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "### Finishing deployment"
Write-Host "####"
Write-Host "########"
Write-Host "############"
#
Write-Host -ForegroundColor Yellow "Adding entry in Azure VM's host file to manage S2D and SDN with WAC"
Add-Content C:\windows\System32\drivers\etc\hosts -Value "$($ConfigData.S2DClusterIP) $($ConfigData.S2DClusterName)"

Write-Host -ForegroundColor Green "Creating SMBSHare containing VHDX template to use with SDNExpress deployment"
New-SmbShare -Name Template -Path $configdata.VHDPath -FullAccess Everyone -ErrorAction SilentlyContinue | out-Null

if ( $configdata.AzureVMadmin -and $configdata.AzureVMPwd) 
{
    $secpasswd = ConvertTo-SecureString $configdata.AzureVMPwd -AsPlainText -Force
    $LocalAzureVMCred = New-Object System.Management.Automation.PSCredential ($configdata.AzureVMadmin, $secpasswd)
}
else 
{
    $account = (get-localuser | ? Description -Match "Built-in account for administraring").name
    $Msg = "Please enter Password for local account $account"
    $LocalAzureVMCred = (Get-Credential -Message $Msg -Credential $account)   
}


#Misc things
Invoke-Command -VMName $configdata.HyperVHosts[0].ComputerName  -Credential $DomainJoinCredential {
    Write-Host -ForegroundColor Green "Mapping SMBSHare on $env:COMPUTERNAME to Z:"
    $AzureVMName = $args[0]; $Cred = $args[1]
    New-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$AzureVMName\Template"  -Credential $Cred -Persistent $true

    Add-MpPreference -ExclusionExtension "vhd"
    Add-MpPreference -ExclusionExtension "vhdx"

} -ArgumentList $env:COMPUTERNAME, $LocalAzureVMCred

Write-Host -ForegroundColor Yellow "Adding a vNIC called Mirror on $($configdata.SwitchName) for port Mirroring purpose" -NoNewline
Write-Host -ForegroundColor Yellow "Run Wireshark upon this vNIC to see all SDN traffic"

Add-VMNetworkAdapter -ManagementOS -SwitchName $($configdata.SwitchName) -Name Mirror 

Write-Host -ForegroundColor Yellow "Configuring all SDN VM as port mirror source and vNIC Mirror as destination" 
Get-VMNetworkAdapter -VMName * | Set-VMNetworkAdapter -PortMirroring Source
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapter -PortMirroring Destination
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 7-1001 -NativeVlanId 0

$HypvHost = $configdata.HyperVHosts[0].ComputerName
Write-Host -ForegroundColor Green `
    "SDN Nested Infrastrucre is ready. You can deploy SDN using SDNExpress.ps1 script. Execute it locally from $HypvHost"