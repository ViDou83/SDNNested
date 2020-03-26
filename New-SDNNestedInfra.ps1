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

import-module .\utils\SDNNested-Module.psm1 -force

# Script version, should be matched with the config files
$ScriptVersion = "2.0"

#Validating passed in config files
if ($psCmdlet.ParameterSetName -eq "ConfigurationFile") 
{
   Write-SDNNestedLog "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
}
elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") 
{
   Write-SDNNestedLog "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) 
{
   Write-SDNNestedLog "Configuration file $ConfigurationDataFile version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express."
   Write-SDNNestedLog "Please update your config file to match the version $scriptversion example."
    return
}

#If not defined, set VMMemory and Processor to default values
if ( $null -eq $ConfigData.VMProcessorCount) { $ConfigData.VMProcessorCount = 2 }
if ( $null -eq $ConfigData.VMMemory) { $ConfigData.VMMemory = 4GB }

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CHECKING AND GETTING CREDENTIALS FROM STDIN"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"

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

#Getting VMHost (LocalVM) credential
if ( $configdata.VMHostadmin -and $configdata.VMHostPwd) 
{
    $secpasswd = ConvertTo-SecureString $configdata.VMHostPwd -AsPlainText -Force
    $VMHostCred = New-Object System.Management.Automation.PSCredential ($configdata.VMHostadmin, $secpasswd)
}
else 
{
    $account = (get-localuser | ? Description -Match "Built-in account for administraring").name
    $Msg = "Please enter Host=$env:ComputerName account=$account "
    $VMHostCred = (Get-Credential -Message $Msg -Credential $account)   
}

Write-SDNNestedLog  "Domain Admin Credential=$DomainJoinUserNameName"
Write-SDNNestedLog  "Local Admin Credential=$LocalAdminDomainUserName"

#Caching DOMAIN Credential
Invoke-Expression -Command `
"cmdkey /add:*.$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null

Write-SDNNestedLog  "Creating SMBSHare on $env:computername to expose VHDX template to SDN-HOST"
New-SmbShare -Name Template -Path $configdata.VHDPath -FullAccess Everyone -ErrorAction SilentlyContinue | out-Null

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "#### This script will deploy Hyper-V hosts and DC to host SDN stack based on the configuration file passed in $ConfigurationDataFile"
Write-SDNNestedLog "#### Checking if all prerequisites before deploying"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
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
    $vmswitch = New-VMSwitch -Name $configdata.SwitchName -SwitchType Internal
    Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) created"
    if( $configdata.ShareHostInternet)
    {
        Write-SDNNestedLog  "Adding Internet Internal's vSwitch in order SDN's VMs having Internet access"
        New-VMSwitch -Name Internet -SwitchType Internal | Out-Null
    }
}    

if ( $vmswitch.name | Where-Object { $_ -eq $configdata.SwitchName } ) 
{ 
   Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) found"
}
else{ throw "No virtual switch $($configdata.SwitchName) found on this host.  Please create the virtual switch before adding this host." }

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CONNECTING $env:computername TO THE SDN SWITCH"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
#That will configure all VMHost vNICs
Connect-HostToSDN $configdata.VMHostvNICs 

<#
    SDN DC DEPLOYMENT
#>
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "###  STARTING DOMAIN CONTROLLER DEPLOYMENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
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
    if( $null -eq $vm)
    {
        $paramsAD.VMName = $dc.ComputerName
        $paramsAD.Nics = $dc.NICs
        #Creating DC with Desktop env 
        $paramsAD.VHDName = $configdata.VHDGUIFile
        $paramsAD.VMMemory =  $dc.VMMemory
        $paramsAD.VMProcessorCount = $dc.VMProcessorCount

        #Creating VM's and stagging OS with unattended provisioning
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
        WaitLocalVMisBooted $dc.computername $DomainJoinCredential

        Write-SDNNestedLog  "Configuring VLAN VLANID=$($dc.NICs[0].VLANID) VM=$($dc.computername)"
        Get-VMNetworkAdapter -VMName $dc.computername | Set-VMNetworkAdapterVlan -Access -VlanId $dc.NICs[0].VLANID

        #Fixing DNS config if DCs has more than vNIC
        if( ($dc.Nics).count -gt 1 )
        {
            Set-DnsConfigBindings $dc.computername $MgmtIp $DomainJoinCredential 
        }
        #Set DNS forwarder if needed 
        if ( $configdata.ShareHostInternet )
        {
            Add-DnsForwarders $dc.computername $true $DomainJoinCredential
        }
    }
    else{   Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
    #Adding credential to the cache
    WaitLocalVMisBooted $dc.computername $DomainJoinCredential
}

<#
    SDN HOST DEPLOYMENT
#>
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING HYPV HOST DEPLOYMNENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
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
        
        #Creating VM's and stagging OS with unattended provisioning
        New-SdnNestedVm @paramsHOST

        #required for nested virtualization
        Write-SDNNestedLog  "Enabling ExposeVirtualizationExtensions on VM $($node.ComputerName)" 
        Get-VM -Name $node.ComputerName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
        #Required to allow multiple MAC per vNIC
        Write-SDNNestedLog  "Enabling MacAddressSpoofing on VMNICs : $($node.ComputerName)" 
        Get-VM -Name $node.ComputerName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On
  
        Write-SDNNestedLog  "Creating VM DataDisks for VM $($node.ComputerName)" 
        if( $ConfigData.S2DEnabled )
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
            $Cred = $args[2]
            
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
                Write-Host  "Formating drive D:\ on $($env:COMPUTERNAME) - Store SDNExpress VMs on it ! "
            }

            Write-Host "Adding Defender files exclusion"
            Add-MpPreference -ExclusionExtension "vhd"
            Add-MpPreference -ExclusionExtension "vhdx"

            #Mapping VHDX's SMB File share 
            $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")
            Write-Host  "$env:COMPUTERNAME : Mapping SMBSHare from \\$LocalVMName\template to Z:"
            New-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$LocalVMName\Template" -Credential $Cred -Persistent $true -Verbose
            Get-SmbGlobalMapping
        } -ArgumentList $Node.NICs[0].VLANID, $ConfigData.S2DEnabled, $VMHostCred
        
        Write-SDNNestedLog "<-- Staging $($node.ComputerName) is done "
        
        Write-SDNNestedLog "Configuring VMNIC on $($node.computername) as dot1q trunk to carry VLANs traffic"
        Get-VMNetworkAdapter -VMName $node.ComputerName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
        #Adding credential to the cache
    }
    else{ Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
}
WaitLocalVMisBooted $configdata.HyperVHosts[-1].Computername $DomainJoinCredential

#Check that all Features are properly installed before moving to the next steps.
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

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### CONFIGURING S2D CLUSTER "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
$result = $false
$result = invoke-command -VMName $configdata.HyperVHosts[-1].Computername -Credential $DomainJoinCredential -ea SilentlyContinue { 
                $S2DClusterName=$args[0]
                if ( (get-cluster).Name -eq $S2DClusterName ){ $true } 
                else{ $false }
            } -ArgumentList $ConfigData.S2DClusterName
if ( $result -ne $ConfigData.S2DClusterName )
{
    if( $ConfigData.S2DEnabled )
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

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING ToR ROUTER DEPLOYMNENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
#Creating ToR Router
$credential = $LocalAdminCredential
$ToR = $configdata.TORrouter

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
        'DnsIpAddr'           = $ConfigData.ManagementDNS;
        'DomainFQDN'          = $ConfigData.DomainFQDN;
        'ProductKey'          = $ConfigData.ProductKey;
    }

    #Creating VM's and stagging OS with unattended provisioning
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
    New-ToRRouter $ToR.ComputerName $credential $ToR

    #fixing VLAN
    $vNICs = Get-VMNetworkAdapter -VMName $ToR.ComputerName

    foreach( $vNIC in $vNICs)
    {
        foreach( $NIC in $ToR.NICs)
        {  
            foreach( $IPAddress in $vNIC.IPAddresses)
            {
                if( $NIC.IPAddress  -match $IPAddress )
                {
                    Write-SDNNestedLog "VLAN config: $($vNIC.Name) IP=$IpAddress VLAN=$($NIC.VLANID)" 
                    $vNIC | Set-VMNetworkAdapterVlan -Access -VlanId $NIC.VlanID
                }
            }
        }
    }
    #
    if ( $ToR.InternetNAT )
    {
        $InternetvNIC = $vNICs | ? IPAddresses -Match $ToR.OutsideNAT
        if ( $InternetvNIC )
        {
            $InternetvNIC | Connect-VMNetworkAdapter -SwitchName Internet
        }
        #Add Dhcp 
        Add-WindowsFeatureOnVM $ToR.ComputerName $credential DHCP
        #
        New-DhcpServer $ToR.ComputerName $configdata.DCs[0].ComputerName `
            $configdata.ManagementDNS $configdata.ManagementSubnet $configdata.ManagementGateway $credential
    }
}
else{Write-SDNNestedLog  "ToR router already configured - Skipping deployment" }

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### STARTING TENANTs GWs DEPLOYMENT "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
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

        #Creating VM's and stagging OS with unattended provisioning
        New-SdnNestedVm @paramsGW 

        Start-VM $GW.ComputerName

        WaitLocalVMisBooted $GW.ComputerName $LocalAdminCredential

        if( $configdata.ShareHostInternet )
        {
            #Add a MGMT interface on each to internet Access through ToR
            Add-VMNetworkAdapter -Name MGMT -VMName $GW.Computername -SwitchName $configdata.SwitchName
            Get-VMNetworkAdapter -Name MGMT -VMName $GW.Computername | Set-VMNetworkAdapterVlan -Access -VlanID $configdata.ManagementVLANID
        }
        
        Add-WindowsFeatureOnVM $GW.ComputerName $LocalAdminCredential RemoteAccess 
        invoke-Command -VMName  $GW.ComputerName  -Credential $LocalAdminCredential {
            #To be able to do PSRemote to Tenant VMs
            winrm set winrm/config/client '@{TrustedHosts="*"}' | Out-Null
        }

        Invoke-Expression -Command `
            "cmdkey /add:$($GW.ComputerName) /user:Administrator /pass:$LocalAdminPassword" | Out-Null
        
        Write-SDNNestedLog  "VM=$($GW.ComputerName) is going to be stopped to save memory"
        stop-vm $GW.ComputerName
    }
    else{Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
}

<# 
    Port Mirroring 
#>
if ( $configdata.PortMirroring )
{
    Write-SDNNestedLog "########"
    Write-SDNNestedLog "####"
    Write-SDNNestedLog "### Configuring Port Mirroring "
    Write-SDNNestedLog "####"
    Write-SDNNestedLog "########"
    
    Write-SDNNestedLog  "Adding a vNIC called Mirror on $($configdata.SwitchName) for port Mirroring purpose" -NoNewline
    Write-SDNNestedLog  "Use Wireshark or Netmon then to sniff all SDN traffic"
    Add-VMNetworkAdapter -ManagementOS -SwitchName $($configdata.SwitchName) -Name Mirror 

    Write-SDNNestedLog  "Configuring all SDN VM as port mirror source and vNIC Mirror as destination" 
    Get-VMNetworkAdapter -VMName * | Set-VMNetworkAdapter -PortMirroring Source
    Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapter -PortMirroring Destination
    Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
}

Invoke-Command -VMName $configdata.HyperVHosts.ComputerName -Credential $DomainJoinCredential {
    $Cred = $args[0]
    $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")

    Write-Host  "$env:COMPUTERNAME :Mapping SMBSHare from \\$LocalVMName\template to Z:"
    New-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$LocalVMName\Template"  -Credential $Cred -Persistent $true
} -ArgumentList $VMHostCred

Write-SDNNestedLog  `
    "SDN Nested Infrastrucre is ready. You can deploy SDN using SDNExpress.ps1 script. Execute it locally from one of deployed SDN-HOST"