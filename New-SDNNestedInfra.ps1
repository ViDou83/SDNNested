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
Write-SDNNestedLog "### Checking and getting credentials"
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
if ( $HypvIsInstalled.InstallState -eq "Installed" ) {
   Write-SDNNestedLog  "Hypv role is $($HypvIsInstalled.installstate)"
}
else {
    throw "Hyper-V Feature needs to be installed in order to deploy SDN nested"    
}
#Checking VMSwitch
$vmswitch = get-vmswitch $($configdata.SwitchName)
if ( $null -eq $vmswitch ) {
   Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) created"
    $vmswitch = New-VMSwitch -Name $configdata.SwitchName -SwitchType Internal
}    

if ( $vmswitch.name | Where-Object { $_ -eq $configdata.SwitchName } ) { 
   Write-SDNNestedLog  "VMSwitch $($configdata.SwitchName) found"
}
else {
    throw "No virtual switch $($configdata.SwitchName) found on this host.  Please create the virtual switch before adding this host."    
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Connecting $env:computername to the SDN switch"
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
Write-SDNNestedLog "###  Start Domain controller deployment "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"

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
    else{Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
    #Adding credential to the cache
    Invoke-Expression -Command `
            "cmdkey /add:$($dc.ComputerName).$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null
}
WaitLocalVMisBooted $configdata.DCs[-1].computername $DomainJoinCredential

<#
    SDN HOST DEPLOYMENT
#>
Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Start Hypv hosts deployment "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
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
    $vm = get-vm $node.Computername -ea silentlycontinue
    if( $null -eq $vm)
    {
        $paramsHOST.VMName = $node.ComputerName
        $paramsHOST.Nics = $node.NICs
        $paramsHOST.VMMemory =  $node.VMMemory
        $paramsHOST.VMProcessorCount = $node.VMProcessorCount
        
        New-SdnNestedVm @paramsHOST

        #required for nested virtualization 
        Get-VM -Name $node.ComputerName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
        #Required to allow multiple MAC per vNIC
        Get-VM -Name $node.ComputerName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On
  
        if( $ConfigData.SDNonS2D )
        {
           Write-SDNNestedLog  "Adding VM S2D DataDisks on $($node.ComputerName)" 
            Add-VMDataDisk $node.ComputerName "S2D" $ConfigData.S2DDiskSize $ConfigData.S2DDiskNumber
        }
        else
        {
           Write-SDNNestedLog  "Adding VM DataDisks on $($node.ComputerName)" 
            Add-VMDataDisk $node.ComputerName "VMs" $node.VMDiskSize 1
            Add-VMDataDisk $node.ComputerName "S2D" 8GB 4
        }

        Start-VM $node.ComputerName 
        
        WaitLocalVMisBooted $node.ComputerName $DomainJoinCredential 

        $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"
        Add-WindowsFeatureOnVM $node.computername $DomainJoinCredential $FeatureList 
        
        Invoke-Command -VMName $node.ComputerName -Credential $DomainJoinCredential {
            $VlanID = $args[0]
            $S2D = $args[1]
            
           Write-SDNNestedLog "Adding SDN VMSwitch on $($env:COMPUTERNAME)"
            New-VMSwitch -NetAdapterName $(Get-Netadapter).Name -SwitchName SDNSwitch -AllowManagementOS $true | Out-Null
            Get-VMNetworkAdapter -ManagementOS -Name SDNSwitch | Rename-VMNetworkAdapter -NewName MGMT
            Get-VMNetworkAdapter -ManagementOS -Name MGMT | Set-VMNetworkAdapterVlan -Access -VlanId $VlanID
            #Cred SSDP for remote administration
           Write-SDNNestedLog "Allowing CredSSP to manage HYPV host $($env:COMPUTERNAME) from local machine"
            Enable-WSManCredSSP -Role Server -Force | Out-Null
            Set-VMHost  -EnableEnhancedSessionMode $true
    
            if( ! $S2D )
            {
                get-disk | ? size -gt 8GB | ? OperationalStatus -eq offline | Initialize-Disk -PassThru | New-Partition -AssignDriveLetter `
                    -UseMaximumSize | Format-Volume | Out-Null
               Write-SDNNestedLog  "Formarting drive D:\ on $($env:COMPUTERNAME) - Store SDNExpress VMs on it ! "
            }

           Write-SDNNestedLog "$env:COMPUTERNAME: Adding Defender files exclusion"
            Add-MpPreference -ExclusionExtension "vhd"
            Add-MpPreference -ExclusionExtension "vhdx"

        } -ArgumentList $Node.NICs[0].VLANID, $ConfigData.SDNonS2D
        
        Get-VMNetworkAdapter -VMName $node.ComputerName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 1-1024 -NativeVlanId 0
        #Adding credential to the cache
        Invoke-Expression -Command `
            "cmdkey /add:$($node.ComputerName).$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null
    }
    else{ Write-SDNNestedLog  "VM=$($vm.Name) already exist - Skipping deployment" }
}


WaitLocalVMisBooted $configdata.HyperVHosts[-1].Computername $DomainJoinCredential
$result = icm -VMName $configdata.HyperVHosts[-1].Computername -Credential $DomainJoinCredential -ea SilentlyContinue { 
                (get-cluster).Name 
            } 

if ( $result -ne $ConfigData.S2DClusterName )
{
    if( $ConfigData.SDNonS2D )
    {
        Write-SDNNestedLog "############"
        Write-SDNNestedLog "########"
        Write-SDNNestedLog "####"
        Write-SDNNestedLog "### Configuring S2D Cluster "
        Write-SDNNestedLog "####"
        Write-SDNNestedLog "########"
        Write-SDNNestedLog "############"

        New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $LocalAdminCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName 
    }
    else
    {
        Write-SDNNestedLog  "### Configuring dummy S2D Cluster to manage SDN through WAC"
        New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $LocalAdminCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName 
    }
    Invoke-Expression -Command `
    "cmdkey /add:$($ConfigData.S2DClusterName).$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword" | Out-Null
}
else{ Write-SDNNestedLog  "$($ConfigData.S2DClusterName) already exist - Skipping S2D deployment" }


Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Start Tenant GW deployment "
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
                } -ArgumentList $TenantvGW
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
Write-SDNNestedLog "### ToR Router deployement "
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

    if ( ! ( icm -VMName $ToR.ComputerName -Credential $credential { if ( Test-Path C:\ToR.txt){$true} } ) )
    {
        New-ToRrouter $configdata.TORrouter.ComputerName $credential $ToR

        #fixing VLAN
        $vNICs = Get-VMNetworkAdapter -VMName $ToR.ComputerName

        foreach( $vNIC in $vNICs)
        {
            foreach( $NIC in $ToR.NICs)
            {  
                foreach( $IPAddress in $vNIC.IPAddresses){
                    if( $NIC.IPAddress  -match $IPAddress ){
                        $vNIC | Set-VMNetworkAdapterVlan -Access -VlanId $NIC.VlanID
                    }
                }
            }
        }
    }
    else{Write-SDNNestedLog  "TOR router already configured - Skipping deployment" }
}

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Finishing deployment"
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
Write-SDNNestedLog  "Creating SMBSHare containing VHDX template to use with SDNExpress deployment"
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
Invoke-Command -VMName $configdata.HyperVHosts.ComputerName  -Credential $LocalAdminCredential {
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