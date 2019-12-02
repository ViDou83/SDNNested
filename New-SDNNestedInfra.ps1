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


Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- This script will deploy Hyper-V hosts and DC to host SDN stack based on the configuration file passed in $ConfigurationDataFile"
Write-Host "--- Checking if all prerequisites before deploying"
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

if ( $vmswitch.name | Where-Object { $_ -eq $paramsHOST.SwitchName } ) { 
    Write-Host -ForegroundColor Green "VMSwitch $($params.SwitchName) found"
}
else {
    throw "No virtual switch $($params.SwitchName) found on this host.  Please create the virtual switch before adding this host."    
}
#Checking if DCs are defined
if ( $null -eq $configdata.DCs ) {
    throw "No Domain Controller configuration defined."    
}

#Checking if DCs are defined
if ( $null -eq $configdata.HyperVHosts ) {
    throw "No Hyper-V Host configuration defined."    
}

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Connecting $env:computername to the SDN switch"
Connect-HostToSDN $configdata.HostSdnNICs $vmswitch.Name $configdata.PublicVIPNetRoute

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start Domain controller deployment "
#Creating DC
foreach ( $dc in $configdata.DCs) 
{
    $paramsAD.VMName = $dc.ComputerName
    $paramsAD.Nics = $dc.NICs
    #Creating DC with Desktop env 
    $paramsAD.VHDName = $configdata.VHDGUIFile

    Write-Host -ForegroundColor Green "Step 1 - Creating DC VM $($dc.ComputerName)" 
    New-SdnNestedVm @paramsAD 

    Start-VM $dc.ComputerName
    Write-host "$($dc.ComputerName) is booting" -NoNewline
    
    while ((Invoke-Command -VMName $dc.ComputerName -Credential $LocalAdminCredential  -ErrorAction Ignore { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $dc.ComputerName) { Start-Sleep -Seconds 1; Write-Host "." -NoNewline }

    New-SDNNestedDC $dc.Compurtename $LocalAdminCredential $configdata.DomainFQDN $LocalAdminPassword

    Write-Host  "Configuring VLAN VLANID=$($dc.NICs[0].VLANID) VM=$($dc.computername)"
    Get-VMNetworkAdapter -VMName $dc.computername | Set-VMNetworkAdapterVlan -Access -VlanId $dc.NICs[0].VLANID
}

#Start-Sleep 60

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start Hypv hosts deployment "
#Creating HYPV Hosts
foreach ( $node in $configdata.HyperVHosts) {
    $paramsHOST.VMName = $node.ComputerName
    $paramsHOST.Nics = $node.NICs
    $paramsHOST.VMMemory =  $node.VMMemory
    $paramsHOST.VMProcessorCount = 4

    Write-Host -ForegroundColor Green "Step 1 - Creating Host VM $($node.ComputerName)" 
    New-SdnNestedVm @paramsHOST

    #required for nested virtualization 
    Get-VM -Name $node.ComputerName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
    #Required to allow multiple MAC per vNIC
    Get-VM -Name $node.ComputerName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On

    Write-Host -ForegroundColor Green "Step 2 - Adding  VM DataDisk for S2D on $($node.ComputerName)" 
    Add-VMDataDisk $node.ComputerName $ConfigData.S2DDiskSize $ConfigData.S2DDiskNumber
 
    Write-Host -ForegroundColor Green  "Step 3 - Starting VM $($node.ComputerName)"
    Start-VM $node.ComputerName 
 
    Write-Host -ForegroundColor yellow "Waiting till the $($node.computername) is not domain joined to $($configdata.DomainFQDN)"
    while ( $( Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential  -ErrorAction Ignore { 
                (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain }) -ne $true ) { Start-Sleep 1 }

    Write-Host -ForegroundColor Green  "Step 4 - Adding required features on VM $($node.ComputerName)"
    Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential {
        $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"
        Add-WindowsFeature $FeatureList 
        Restart-Computer -Force
    }

    Write-host "Wait till the VM $($node.ComputerName) is not WinRM reachable"
    
    Start-Sleep 30
    
    while ((Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential  -ErrorAction Ignore { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $node.ComputerName) { Start-Sleep -Seconds 1 }  

    Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential {
        Write-Host -ForegroundColor Green "Step 5 - Adding SDN VMSwitch on $($env:COMPUTERNAME)"
        New-VMSwitch -NetAdapterName $(Get-Netadapter).Name -SwitchName SDNSwitch -AllowManagementOS $true | Out-Null
        Get-VMNetworkAdapter -ManagementOS -Name SDNSwitch | Rename-VMNetworkAdapter -NewName MGMT
        Get-VMNetworkAdapter -ManagementOS -Name MGMT | Set-VMNetworkAdapterVlan -Access -VlanId $args[0]
        #Cred SSDP for remote administration
        Write-Host -ForegroundColor Green "Step 6 - Allowing CredSSP to managed HYPV host $($env:COMPUTERNAME) from Azure VM"
        Enable-WSManCredSSP -Role Server -Force
        Set-VMHost  -EnableEnhancedSessionMode $true
    } -ArgumentList $Node.NICs[0].VLANID
    
    Get-VMNetworkAdapter -VMName $node.ComputerName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
    #Adding credential to the cache
    Invoke-Expression -Command "cmdkey /add:$($node.ComputerName).$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword"
}

#$password = $DomainJoinPassword | ConvertTo-SecureString -asPlainText -Force
#$DomainJoinCredential = New-Object System.Management.Automation.PSCredential($ConfigData.DomainJoinUserName, $password)

Start-Sleep 60

Write-Host -ForegroundColor Green "Step 6 - Creating new S2D Failover cluster for Hyperconverged SDN"
New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $DomainJoinCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName 

Write-Host -ForegroundColor Yellow "Adding entry in Azure VM's host file to manage S2D and SDN with WAC"
Add-Content C:\windows\System32\drivers\etc\hosts -Value "$($ConfigData.S2DClusterIP) $($ConfigData.S2DClusterName)"

Write-Host -ForegroundColor Green "SDN HyperConverged Cluster is ready."
Write-Host -ForegroundColor Green ""

Write-Host -ForegroundColor Green "Creating SMBSHare containing VHDX template to use with SDNExpress deployment"
New-SmbShare -Name Template -Path $configdata.VHDPath -FullAccess Everyone

$account = (get-localuser | ? Description -Match "Built-in account for administraring").name
$Msg = "Please enter Password for local account $account"

if ( $configdata.AzureVMadmin -and $configdata.AzureVMPwd) {
    $secpasswd = ConvertTo-SecureString $configdata.AzureVMPwd -AsPlainText -Force
    $LocalAzureVMCred = New-Object System.Management.Automation.PSCredential ($configdata.AzureVMadmin, $secpasswd)
}
else {
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


#####Move back
Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start outside SDN stack Tenant GW deployment "
#Creating Gw Hosts
foreach ( $GW in $configdata.TenantInfraGWs) {
    $paramsGW.VMName = $GW.ComputerName
    $paramsGW.Nics = $GW.NICs

    Write-Host -ForegroundColor Green "Step 1 - Creating GW VM $($GW.ComputerName)" 
    New-SdnNestedVm @paramsGW 

    Start-VM $GW.ComputerName
    Write-host "Wait till the VM $($GW.ComputerName) is not WinRM reachable"
    while ((Invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential  -ErrorAction Ignore { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $GW.ComputerName) { Start-Sleep -Seconds 1 }

    foreach ( $TenantvGW in $configdata.TenantvGWs) {
        #"$($TenantvGW.tenant) ==  $($Tenant.name) => $($Tenant.PhysicalGwVMName)"
        if ( $TenantvGW.Tenant -eq $GW.Tenant ) {
            invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential {
                $TenantvGW = $args[0]
                Write-Host -ForegroundColor Yellow "Checking IP config from $($TenantvGW.VirtualGwName) config"
            
                Write-Host -ForegroundColor Green "Adding Remote Access feature on $env:COMPUTERNAME"
                $res = Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools

                if ( $res.RestartNeeded -eq "Yes" ) { Restart-Computer -Force; Write-host "Rebooting $env:COMPUTERNAME" }
            } -ArgumentList $TenantvGW
            
            Sleep 30

            while ((Invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential  -ErrorAction Ignore { $env:COMPUTERNAME } `
                        -ea SilentlyContinue) -ne $GW.ComputerName) { Start-Sleep -Seconds 1 }

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

#####Move back
Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- ToR Router deployement "
#Creating Gw Hosts
foreach ( $ToR in $configdata.TORrouter) 
{

    $credential = $DomainJoinCredential

    if ( ! (get-vm $ToR.Compurtername) ){
        $paramsToR = @{
            'VMLocation'          = $ConfigData.VMLocation;
            'VMName'              = $ToR.Compurtename;
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

    }

    while ((Invoke-Command -VMName $ToR.ComputerName -Credential $credential  -ErrorAction Ignore { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $ToR.ComputerName) { Start-Sleep -Seconds 1 }

    New-ToRrouter $configdata.TORrouter.Compurtename $DomainJoinCredential $ToR

}


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