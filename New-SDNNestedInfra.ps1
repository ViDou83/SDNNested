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
Deploy SDNv2 Stack based on configuration Data File provided 

.EXAMPLE

.NOTES
contact vidou@microsoft.com for any questions/remark/improvements

#>
[CmdletBinding(DefaultParameterSetName = "NoParameters")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = ".\configfiles\SMALL\SDNNested-Deploy-Infra.psd1"
)    

#import-module .\SDNExpress\SDNExpressModule.psm1 -force
import-module .\utils\SDNNested-Module.psm1 -force

# Script version, should be matched with the config files
$ScriptVersion = "2.0"

#Validating passed in config files
if ($psCmdlet.ParameterSetName -eq "ConfigurationFile") {
   Write-SDNNestedLog "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
}
elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
   Write-SDNNestedLog "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
   Write-SDNNestedLog "Configuration file $ConfigurationDataFile version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express."
   Write-SDNNestedLog "Please update your config file to match the version $scriptversion example."
    return
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CHECKING AND GETTING CREDENTIALS FROM STDIN"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"

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

#If not defined, set VMMemory and Processor to default values
if ( $null -eq $ConfigData.VMProcessorCount) { $ConfigData.VMProcessorCount = 2 }
if ( $null -eq $ConfigData.VMMemory) { $ConfigData.VMMemory = 4GB }

Write-SDNNestedLog  "Domain Admin Credantial=$DomainJoinUserNameName"
Write-SDNNestedLog  "Local Admin Credantial=$LocalAdminDomainUserName"

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "#### This script will deploy Hyper-V hosts and DC to host SDN stack based on the configuration file passed in $ConfigurationDataFile"
Write-SDNNestedLog "#### Checking if all prerequisites before deploying"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
#Checking Hyper-V role
$HypvIsInstalled = Get-WindowsFeature Hyper-V
if ( $HypvIsInstalled.InstallState -eq "Installed" )
{
    Write-SDNNestedLog  "Hypv role is $($HypvIsInstalled.installstate)"
}
else{ throw "Hyper-V Feature needs to be installed in order to deploy SDN nested" }

#Checking VMSwitch
$vmswitch = get-vmswitch $($configdata.SwitchName) -ErrorAction SilentlyContinue
if ( ! $vmswitch ) 
{
    Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) created"
    $vmswitch = New-VMSwitch -Name $configdata.SwitchName -SwitchType Internal
}    

if ( $vmswitch.name | Where-Object { $_ -eq $configdata.SwitchName } ) 
{ 
   Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) found"
}
else{ throw "No virtual switch $($configdata.SwitchName) found on this host.  Please create the virtual switch before adding this host." }

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CONNECTING $env:computername TO THE SDN SWITCH"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
Connect-HostToSDN $configdata.HostSdnNICs $vmswitch.Name $configdata.PublicVIPNetRoute

<#
    SDN DC DEPLOYMENT
#>
Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "###  STARTING DOMAIN CONTROLLER DEPLOYMENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"

#Checking if DCs are defined
if ( $null -eq $configdata.DCs ){ throw "No Domain Controller configuration defined." }

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
    $vm = get-vm $dc.Computername -ea silentlycontinue
    if( $null -eq $vm){
        $paramsAD.VMName = $dc.ComputerName
        $paramsAD.Nics = $dc.NICs
        #Creating DC with Desktop env 
        $paramsAD.VHDName = $configdata.VHDGUIFile
        $paramsAD.VMMemory =  $dc.VMMemory
        $paramsAD.VMProcessorCount = $dc.VMProcessorCount

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
        Write-SDNNestedLog  "Configuring VLAN VLANID=$($dc.NICs[0].VLANID) VM=$($dc.computername)"
        Get-VMNetworkAdapter -VMName $dc.computername | Set-VMNetworkAdapterVlan -Access -VlanId $dc.NICs[0].VLANID
    }
    else{   Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
    #Adding credential to the cache

    WaitLocalVMisBooted $dc.computername $DomainJoinCredential
}

<#
    SDN HOST DEPLOYMENT
#>
Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING HYPV HOST DEPLOYMNENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
#Checking if HYVP HOSTs are defined
if ( $null -eq $configdata.HyperVHosts ){ throw "No Hyper-V Host configuration defined." }

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
    $vm = get-vm $node.Computername -ea silentlycontinue
    if( $null -eq $vm)
    {
        $paramsHOST.VMName = $node.ComputerName
        $paramsHOST.Nics = $node.NICs
        $paramsHOST.VMMemory =  $node.VMMemory
        $paramsHOST.VMProcessorCount = $node.VMProcessorCount
        
        New-SdnNestedVm @paramsHOST

        #required for nested virtualization
        Write-SDNNestedLog  "Enabling ExposeVirtualizationExtensions on VM $($node.ComputerName)" 
        Get-VM -Name $node.ComputerName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
        #Required to allow multiple MAC per vNIC
        Write-SDNNestedLog  "Enabling MacAddressSpoofing on VMNis : $($node.ComputerName)" 
        Get-VM -Name $node.ComputerName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On
  
        Write-SDNNestedLog  "Creating VM DataDisks for VM $($node.ComputerName)" 
        if( $ConfigData.SDNonS2D )
        {
            Add-VMDataDisk $node.ComputerName "S2D" $ConfigData.S2DDiskSize $ConfigData.S2DDiskNumber
        }
        else
        {
            Add-VMDataDisk $node.ComputerName "VMs" $node.VMDiskSize 1
            Add-VMDataDisk $node.ComputerName "S2D" 4GB 4
        }

        Start-VM $node.ComputerName 
        WaitLocalVMisBooted $node.ComputerName $DomainJoinCredential 

        Write-SDNNestedLog "--> Staging $($node.ComputerName)"
        $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"
        Add-WindowsFeatureOnVM $node.computername $DomainJoinCredential $FeatureList 
        
        Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential -ErrorAction SilentlyContinue {
            $VlanID = $args[0]
            $S2D = $args[1]
            
            Write-Host "Adding SDN VMSwitch"
            New-VMSwitch -NetAdapterName $(Get-Netadapter).Name -Name SDNSwitch -EnableEmbeddedTeaming $true | Out-Null
           
            Write-Host "Adding MGMT Host vNIC SDN VMSwitch and configuring VLAN=$VLanID"
            Get-VMNetworkAdapter -ManagementOS | Rename-VMNetworkAdapter -NewName MGMT     
            Get-VMNetworkAdapter -ManagementOS -Name MGMT | Set-VMNetworkAdapterVlan -Access -VlanId $VlanID

            Write-Host "Configuring Ehternet Jumbo Frame 9K bytes"
            Get-NetAdapter | Get-NetAdapterAdvancedProperty | ? RegistryKeyword -EQ "*JumboPacket" | Set-NetAdapterAdvancedProperty -RegistryValue 9014

            #Cred SSDP for remote administration
            Write-Host "Enabling WSManCredSSP and  EnableEnhancedSessionMode"
            Enable-WSManCredSSP -Role Server -Force | Out-Null
            Set-VMHost  -EnableEnhancedSessionMode $true
    
            if( ! $S2D )
            {
                get-disk | ? size -gt 8GB | ? OperationalStatus -eq offline | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter `
                    -UseMaximumSize | Format-Volume | Out-Null
                Write-Host  "Formarting drive D:\ on $($env:COMPUTERNAME) - Store SDNExpress VMs on it ! "
            }

            Write-Host "Adding Defender files exclusion"
            Add-MpPreference -ExclusionExtension "vhd"
            Add-MpPreference -ExclusionExtension "vhdx"

        } -ArgumentList $Node.NICs[0].VLANID, $ConfigData.SDNonS2D
        Write-SDNNestedLog "<-- Staging $($node.ComputerName) is done "
        
        Write-SDNNestedLog "Configuring VMNIC on $($node.computername) as dot1q trunk to carry VLANs traffic"
        Get-VMNetworkAdapter -VMName $node.ComputerName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
        #Adding credential to the cache
    }
    else{ Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
}

WaitLocalVMisBooted $configdata.HyperVHosts[-1].Computername $DomainJoinCredential

#Check that all Features are well installed.
foreach ( $node in $configdata.HyperVHosts) 
{
    $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"

    Write-SDNNestedLog "Checking that all needed features are installed on $($node.ComputerName)"
    foreach( $Feature in $FeatureList)
    {        
        $result = $true
        $result= invoke-command -VMName $node.ComputerName -Credential $DomainJoinCredential -ea SilentlyContinue { 
            $Feature=$args[0]
            (Get-WindowsFeature $Feature).installed 
        } -ArgumentList $Feature

        if ( ! $result )
        {
            Write-SDNNestedLog "Feature $Feature is not installed on $($node.ComputerName)"
            Add-WindowsFeatureOnVM $node.computername $DomainJoinCredential $Feature 
        }
    }
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CONFIGURING S2D CLUSTER "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
$result = $false
$result = invoke-command -VMName $configdata.HyperVHosts[-1].Computername -Credential $DomainJoinCredential -ea SilentlyContinue { 
                $S2DClusterName=$args[0]
                if ( (get-cluster).Name -eq $S2DClusterName ){ $true } 
                else{ $false }
            } -ArgumentList $ConfigData.S2DClusterName
if ( $result -ne $ConfigData.S2DClusterName )
{
    if( $ConfigData.SDNonS2D )
    {
        New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $DomainJoinCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName $false
    }
    else
    {
        Write-SDNNestedLog  "### Configuring dummy S2D Cluster to manage SDN through WAC"
        New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $DomainJoinCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName $true
    }
}
else{ Write-SDNNestedLog "$($ConfigData.S2DClusterName) already exist - Skipping S2D deployment" }


Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING TENANTs GWs DEPLOYMENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
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
foreach ( $GW in $configdata.TenantInfraGWs) 
{
    $vm = get-vm $GW.Computername -ea silentlycontinue
    if( $null -eq $vm)
    {
        $paramsGW.VMName = $GW.ComputerName
        $paramsGW.Nics = $GW.NICs

        New-SdnNestedVm @paramsGW 

        Start-VM $GW.ComputerName

        WaitLocalVMisBooted $GW.ComputerName $LocalAdminCredential

        foreach ( $TenantvGW in $configdata.TenantvGWs) {
            if ( $TenantvGW.Tenant -eq $GW.Tenant ) 
            {
                Add-WindowsFeatureOnVM $GW.ComputerName $LocalAdminCredential RemoteAccess 

                Write-SDNNestedLog "--> Staging $($GW.ComputerName) "
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
                    Write-Host "Installing Remote Access VPNtype=$VpnType on $env:COMPUTERNAME"
                    Install-RemoteAccess -VpnType $VpnType  
                
                    $run = (Get-Service RemoteAccess).status
                    if ( $run -ne "Running") { Start-Service RemoteAccess }

                    if (  $tunnelMode ) 
                    {
                       Write-Host  "Configuring $($TenantvGW.Type) tunnel on $env:COMPUTENAME"
                        if ( $TenantvGW.Type -eq "GRE") {
                            #GRE VIP POOL
                            if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $TenantvGW.GrePeer) ) { 
                                Write-Host  "IP Address $($TenantvGW.GrePeer) is missing so adding it"
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
                            Write-Host  "IP Address $($TenantvGW.PeerIpAddrGW) is missing so adding it"
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

                    #To be able to do PSRemote to Tenant VMs
                    winrm set winrm/config/client '@{TrustedHosts="*"}' | Out-Null

                } -ArgumentList $TenantvGW
                Write-SDNNestedLog "--> Staging $($GW.ComputerName) is done"
            }     
        }
        
        Invoke-Expression -Command `
            "cmdkey /add:$($GW.ComputerName) /user:Administrator /pass:$LocalAdminPassword" | Out-Null
        
        Write-SDNNestedLog  "VM=$($GW.ComputerName) is going to be stopped to save memory"
        stop-vm $GW.ComputerName
    }
    else{Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING ToR ROUTER DEPLOYMNENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
#Creating ToR Router
foreach ( $ToR in $configdata.TORrouter) 
{
    $credential = $LocalAdminCredential
    if ( $ToR.ComputerName -eq $configdata.DCs[0].computername )
    { 
        $credential = $DomainJoinCredential 
    }

    #If deploying ToR on dedicated VM otherwise deploy it on the existing one 'DC in general'
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

        Start-VM $ToR.ComputerName

        WaitLocalVMisBooted $ToR.ComputerName $credential

        Invoke-Expression -Command `
            "cmdkey /add:$($ToR.ComputerName) /user:Administrator /pass:$LocalAdminPassword" | Out-Null
    }

    #Checking is ToR is not already configured
    $result = invoke-command  -VMName $ToR.ComputerName -Credential $credential { 
                if ( Test-Path C:\ToR.txt){ $true   }
                else { $false }
            } 
    if ( ! ( $result ) )
    {
        Write-SDNNestedLog "--> Tor Router : Staging $($ToR.ComputerName)"
        New-ToRrouter $configdata.TORrouter.ComputerName $credential $ToR

        #fixing VLAN
        $vNICs = Get-VMNetworkAdapter -VMName $ToR.ComputerName

        foreach( $vNIC in $vNICs)
        {
            foreach( $NIC in $ToR.NICs)
            {  
                foreach( $IPAddress in $vNIC.IPAddresses)
                {
                    if( $NIC.IPAddress  -match $IPAddress ){
                        $vNIC | Set-VMNetworkAdapterVlan -Access -VlanId $NIC.VlanID
                    }
                }
            }
        }
        Write-SDNNestedLog "--> Tor Router : Staging $($ToR.ComputerName) is done"
    }
    else{Write-SDNNestedLog  "TOR router already configured - Skipping deployment" }
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### FINISHING DEPLOYMENT"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
#
<#
if( $ConfigData.S2DClusterName )
{
   Write-SDNNestedLog  "Adding entry in Azure VM's host file to manage S2D and SDN with WAC"
    Add-Content C:\windows\System32\drivers\etc\hosts -Value "$($ConfigData.S2DClusterIP) $($ConfigData.S2DClusterName)"
}
#>
Invoke-Expression -Command `
"cmdkey /add:*.$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null

Write-SDNNestedLog  "Creating SMBSHare on $env:computername to expose VHDX template to SDN-HOST"
New-SmbShare -Name Template -Path $configdata.VHDPath -FullAccess Everyone -ErrorAction SilentlyContinue | out-Null

if ( $configdata.VMHostadmin -and $configdata.VMHostPwd) 
{
    $secpasswd = ConvertTo-SecureString $configdata.VMHostPwd -AsPlainText -Force
    $VMHostCred = New-Object System.Management.Automation.PSCredential ($configdata.VMHostadmin, $secpasswd)
}
else 
{
    $account = (get-localuser | ? Description -Match "Built-in account for administraring").name
    $Msg = "Please enter Password for local account $account"
    $VMHostCred = (Get-Credential -Message $Msg -Credential $account)   
}

#Misc things
Write-SDNNestedLog "Mapping SMBSHare \\$LocalVMName\template to Z: on SDN HOSTs"
Invoke-Command -VMName $configdata.HyperVHosts.ComputerName  -Credential $DomainJoinCredential {
    $Cred = $args[0]
    $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")

    Write-Host  "$env:COMPUTERNAME :Mapping SMBSHare from \\$LocalVMName\template to Z:"
    New-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$LocalVMName\Template"  -Credential $Cred -Persistent $true
} -ArgumentList $VMHostCred

Write-SDNNestedLog  "Adding a vNIC called Mirror on $($configdata.SwitchName) for port Mirroring purpose" -NoNewline
Write-SDNNestedLog  "Run Wireshark upon this vNIC to see all SDN traffic"
Add-VMNetworkAdapter -ManagementOS -SwitchName $($configdata.SwitchName) -Name Mirror 

Write-SDNNestedLog  "Configuring all SDN VM as port mirror source and vNIC Mirror as destination" 
Get-VMNetworkAdapter -VMName * | Set-VMNetworkAdapter -PortMirroring Source
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapter -PortMirroring Destination
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0

Write-SDNNestedLog  `
    "SDN Nested Infrastrucre is ready. You can deploy SDN using SDNExpress.ps1 script. Execute it locally from one of deployed SDN-HOST"