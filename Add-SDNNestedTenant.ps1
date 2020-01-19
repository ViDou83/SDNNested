[CmdletBinding(DefaultParameterSetName = "NoParameters")]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = $null,
    [Parameter(Mandatory = $true, ParameterSetName = "ConfigurationData")]
    [object] $ConfigurationData = $null,
    [Switch] $SkipValidation,
    [Switch] $SkipDeployment,
    [PSCredential] $DomainJoinCredential = $null,
    [PSCredential] $NCCredential = $null,
    [PSCredential] $LocalAdminCredential = $null
)    

$feature = get-windowsfeature "RSAT-NetworkController"
if ($feature -eq $null) {
    throw "SDN Express requires Windows Server 2016 or later."
}
if (!$feature.Installed) {
    add-windowsfeature "RSAT-NetworkController"
}

import-module networkcontroller  
import-module .\utils\SDNNested-Module.psm1
#import-module .\SDNExpress\SDNExpressModule.psm1

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

if ($configdata.ScriptVersion -ne $scriptversion) {
   Write-SDNNestedLog "Configuration file version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express." -NoNewline
   Write-SDNNestedLog "Please update your config file to match the version $scriptversion example."
    return
}

#Get credentials for provisionning
$DomainJoinCredential = GetCred $ConfigData.DomainJoinSecurePassword $DomainJoinCredential `
    "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
$LocalAdminCredential = GetCred $ConfigData.LocalAdminSecurePassword $LocalAdminCredential `
    "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

$DomainJoinPassword = $DomainJoinCredential.GetNetworkCredential().Password
$LocalAdminPassword = $LocalAdminCredential.GetNetworkCredential().Password

$DomainJoinUserNameDomain = $configdata.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $configdata.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $configdata.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $configdata.LocalAdminDomainUser.Split("\")[1]

$uri = $configdata.RestURI   

$check = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri -PassInnerException -erroraction SilentlyContinue
if ( ! $check )
{
    $exception = $error.exception[0].innerexception
    throw "ERROR: $exception. Stop Execution"
}


#Find the Access Control List to user per virtual subnet  
#$acllist = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId "AllowAll"  
#Find the HNV Provider Logical Network  
$logicalnetworks = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri  
    
foreach ($ln in $logicalnetworks) {  
    if ($ln.Properties.NetworkVirtualizationEnabled -eq "True") {  
        $HNVProviderLogicalNetwork = $ln  
    }  
}   
  
foreach ($Tenant in $configdata.Tenants) {
    #Create the Virtual Subnet  
    Write-SDNNestedLog  "Pushing VNET config for $($Tenant.Name) to $uri"
    $vsubnet = new-object Microsoft.Windows.NetworkController.VirtualSubnet  
    $vsubnet.ResourceId = $Tenant.TenantVirtualSubnetId  
    $vsubnet.Properties = new-object Microsoft.Windows.NetworkController.VirtualSubnetProperties  
    #$vsubnet.Properties.AccessControlList = $acllist  
    $vsubnet.Properties.AddressPrefix = $Tenant.TenantVirtualSubnetAddressPrefix   
    
    #Create the Virtual Network
    $vnetproperties = new-object Microsoft.Windows.NetworkController.VirtualNetworkProperties  
    $vnetproperties.AddressSpace = new-object Microsoft.Windows.NetworkController.AddressSpace  
    $vnetproperties.AddressSpace.AddressPrefixes = $Tenant.TenantVirtualNetworkAddressPrefix    
    $vnetproperties.LogicalNetwork = $HNVProviderLogicalNetwork  
    $vnetproperties.Subnets = @($vsubnet)  
    $vnet = New-NetworkControllerVirtualNetwork -ResourceId $Tenant.TenantVirtualNetworkName -ConnectionUri $uri `
        -Properties $vnetproperties -Force 

    $vnet

    $gwPool = Get-NetworkControllerGatewayPool -ConnectionUri $uri  

    foreach ($Gw in $configdata.TenantvGWs) 
    {    
        if ( $Gw.Tenant -eq $Tenant.Name) 
        { 
           Write-SDNNestedLog  "Pushing vGW config for $($Tenant.Name) to $uri"
            
            # Create a new object for Tenant Virtual Gateway  
            $VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties   

            # Update Gateway Pool reference  
            $VirtualGWProperties.GatewayPools = @()   
            $VirtualGWProperties.GatewayPools += $gwPool   

            # Specify the Virtual Subnet that is to be used for routing between the gateway and Virtual Network   
            $VirtualGWProperties.GatewaySubnets = @()   
            $VirtualGWProperties.GatewaySubnets += $Vnet.Properties.Subnets

            # Update the rest of the Virtual Gateway object properties  
            $VirtualGWProperties.RoutingType = "Dynamic"   
            $VirtualGWProperties.NetworkConnections = @()   
            $VirtualGWProperties.BgpRouters = @()   
            $Vnet.Properties.Subnets
            # Add the new Virtual Gateway for tenant   
            $virtualGW = New-NetworkControllerVirtualGateway -ConnectionUri $uri -ResourceId "$($Gw.VirtualGwName)" `
                -Properties $VirtualGWProperties -Force 

            $VirtualGW
            
            # Create a new object for the Tenant Network Connection  
            $nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties   

            if ( $gw.Type -eq "L3") {
                # Create a new object for the Logical Network to be used for L3 Forwarding  
                $lnProperties = New-Object Microsoft.Windows.NetworkController.LogicalNetworkProperties  

                $lnProperties.NetworkVirtualizationEnabled = $false  
                $lnProperties.Subnets = @()  

                # Create a new object for the Logical Subnet to be used for L3 Forwarding and update properties  
                $logicalsubnet = New-Object Microsoft.Windows.NetworkController.LogicalSubnet  
                $logicalsubnet.ResourceId = $gw.LogicalSunetName 
                $logicalsubnet.Properties = New-Object Microsoft.Windows.NetworkController.LogicalSubnetProperties  
                $logicalsubnet.Properties.VlanID = $gw.VLANID 
                $logicalsubnet.Properties.AddressPrefix = $gw.LogicalSunetAddressPrefix 
                $logicalsubnet.Properties.DefaultGateways = $gw.LogicalSunetDefaultGateways
                    
                $lnProperties.Subnets += $logicalsubnet  
                    
                $logicalsubnet  

                # Add the new Logical Network to Network Controller  
                $LogicalNetwork = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri | ? ResourceId -eq $Gw.LogicalNetworkName
                if ( $null -eq $LogicalNetwork) {
                    $LogicalNetwork = New-NetworkControllerLogicalNetwork -ConnectionUri $uri `
                        -ResourceId $Gw.LogicalNetworkName -Properties $lnProperties -Force
                }
                    
                $logicalNetwork

                # Update the common object properties  
                $nwConnectionProperties.ConnectionType = $gw.Type
                $nwConnectionProperties.OutboundKiloBitsPerSecond = 10000   
                $nwConnectionProperties.InboundKiloBitsPerSecond = 10000   

                # GRE specific configuration (leave blank for L3)  
                $nwConnectionProperties.GreConfiguration = New-Object Microsoft.Windows.NetworkController.GreConfiguration   

                # Update specific properties depending on the Connection Type  
                $nwConnectionProperties.L3Configuration = New-Object Microsoft.Windows.NetworkController.L3Configuration   
                $nwConnectionProperties.L3Configuration.VlanSubnet = $LogicalNetwork.properties.Subnets[0]   

                $nwConnectionProperties.IPAddresses = @()   
                $localIPAddress = New-Object Microsoft.Windows.NetworkController.CidrIPAddress   
                $localIPAddress.IPAddress = $gw.LocalIpAddrGW   
                $localIPAddress.PrefixLength = ($gw.LogicalSunetAddressPrefix).split("/")[1]
                $nwConnectionProperties.IPAddresses += $localIPAddress   

                $nwConnectionProperties.PeerIPAddresses = $gw.PeerIpAddrGW   
            }
            elseif ($gw.type -eq "GRE") {

                # Update the common object properties  
                $nwConnectionProperties.ConnectionType = $gw.type
                $nwConnectionProperties.OutboundKiloBitsPerSecond = 10000   
                $nwConnectionProperties.InboundKiloBitsPerSecond = 10000   

                # Update specific properties depending on the Connection Type  
                $nwConnectionProperties.GreConfiguration = New-Object Microsoft.Windows.NetworkController.GreConfiguration   
                $nwConnectionProperties.GreConfiguration.GreKey = $Gw.PSK   

                # Tunnel Destination (Remote Endpoint) Address  
                $nwConnectionProperties.DestinationIPAddress = $Gw.GrePeer

                # L3 specific configuration (leave blank for GRE)  
                $nwConnectionProperties.L3Configuration = New-Object Microsoft.Windows.NetworkController.L3Configuration   
                $nwConnectionProperties.IPAddresses = @()   
                $nwConnectionProperties.PeerIPAddresses = @()   
            }

            # Update the IPv4 Routes that are reachable over the site-to-site VPN Tunnel  
            $nwConnectionProperties.Routes = @()   
            
            foreach ( $RouteDstPrefix in $Gw.RouteDstPrefix) {
                $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo   
                $ipv4Route.DestinationPrefix = $RouteDstPrefix
                if ( $gw.Type -eq "L3") { $ipv4Route.NextHop = $Gw.PeerIpAddrGW[0] }
                $ipv4Route.metric = 10   
                $nwConnectionProperties.Routes += $ipv4Route   
            }

            # Add the new Network Connection for the tenant
            New-NetworkControllerVirtualGatewayNetworkConnection -ConnectionUri $uri -VirtualGatewayId $virtualGW.ResourceId `
                -ResourceId "nwConnection_$($gw.Type)" -Properties $nwConnectionProperties -Force

            #Configure BGP on the vGW 
            if ( $gw.BGPEnabled -eq $True) 
            {     
                Write-SDNNestedLog  "Pushing BGP config for $($Tenant.name) vGW to $uri"

                # Create a new object for the Tenant BGP Router  
                $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties   

                # Update the BGP Router properties  
                $bgpRouterproperties.ExtAsNumber = $gw.BgpLocalExtAsNumber
                $bgpRouterproperties.RouterId = $gw.BgpLocalBRouterId
                $bgpRouterproperties.RouterIP = $gw.BgpLocalRouterIP  
                    
                # Add the new BGP Router for the tenant  
                $bgpRouter = New-NetworkControllerVirtualGatewayBgpRouter -ConnectionUri $uri -VirtualGatewayId $virtualGW.ResourceId `
                    -ResourceId "$($virtualGW.ResourceId)_$($gw.Type)_BGPRouter" -Properties $bgpRouterProperties -Force

                # Create a new object for Tenant BGP Peer  
                $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties   

                # Update the BGP Peer properties  
                $bgpPeerProperties.PeerIpAddress = $gw.BgpPeerIpAddress   
                $bgpPeerProperties.AsNumber = $gw.BgpPeerAsNumber   
                $bgpPeerProperties.ExtAsNumber = $gw.BgpPeerExtAsNumber 

                # Add the new BGP Peer for tenant  
                New-NetworkControllerVirtualGatewayBgpPeer -ConnectionUri $uri -VirtualGatewayId $virtualGW.ResourceId -BgpRouterName $bgpRouter.ResourceId `
                    -ResourceId "BgpRouter_$( $Gw.Tenant)_$($gw.Type)_BGPPeerAs$($Gw.BgpPeerAsNumber)" -Properties $bgpPeerProperties -Force
            }
        }
    }
}

#####################
############## CREATING TENANTS VM
#######
#Adding the VM for each tenant
$paramsTenant = @{
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
    'DnsIpAddr'           = $ConfigData.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
}

foreach ($TenantVM in $configdata.TenantVMs) 
{
    $uri = $configdata.RestURI

    $vm = Get-VM -ComputerName $TenantVM.HypvHostname | ? Name -eq $TenantVM.Name
    
    if ($null -eq $vm) 
    { 
        Write-SDNNestedLog  "Adding VM=$($TenantVM.Name) on HYPV=$($TenantVM.HypvHostname) for tenant=$($TenantVM.tenant)"
        $paramsTenant.VMName = $TenantVM.Name
        $paramsTenant.NICs = $TenantVM.NICs
        if ( $TenantVM.VHDFile){  $paramsTenant.VHDName = $TenantVM.VHDFile}
        if ( $TenantVM.VMMemory){ $paramsTenant.VMMemory = $TenantVM.VMMemory}
        if ( $TenantVM.VMProcessorCount){ $paramsTenant.VMProcessorCount = $TenantVM.VMProcessorCount}
        #$paramsTenant.HypvHost = $TenantVM.HypvHostname
    
        $secpasswd = ConvertTo-SecureString $paramsTenant.LocalAdminPassword -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("administrator", $secpasswd)

        Invoke-Command -ComputerName $TenantVM.HypvHostname {
            $paramsTenant = $args[0]
            $TenantVM = $args[1]
            $cred = $args[2]
            
            if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested\utils\SDNNested-Module.psm1 }

            New-SdnNestedVm @paramsTenant

            $feature = get-windowsfeature "RSAT-NetworkController"
            if ($feature -eq $null) {
                throw "SDN Express requires Windows Server 2016 or later."
            }
            if (!$feature.Installed) {
                add-windowsfeature "RSAT-NetworkController"
            }

            import-module networkcontroller  

            try {
                Start-VM $TenantVM.Name -ErrorAction stop
            }
            catch { 
                Write-SDNNestedLog  "VM $($TenantVM.Name) cannot be started on $env:Computername. Stopping script execution"       
                break;
            }
            
            WaitLocalVMisBooted $TenantVM.Name $cred

            Write-SDNNestedLog "Stopping VM $($TenantVM.Name)"
            Stop-VM -VMName $TenantVM.Name -Force 
        } -ArgumentList $paramsTenant,$TenantVM, $cred

        #Creating NIC object on NCs
        foreach ( $NIC in $TenantVM.NICs) 
        {
            $vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
            $vmnicproperties.PrivateMacAllocationMethod = "Dynamic"                
            $vmnicproperties.IsPrimary = $true 
            $vmnicResourceId = "$($TenantVM.Name)_VMNIC0"

            $vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
            $vmnicproperties.DnsSettings.DnsServers = $TenantVM.NICs[0].DNS

            $ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
            $ipconfiguration.resourceid = "$($TenantVM.Name)_IP0"
            $ipconfiguration.properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
            $ipconfiguration.properties.PrivateIPAddress = ($NIC.IPAddress).split("/")[0]
            $ipconfiguration.properties.PrivateIPAllocationMethod = "Static"

            $ipconfiguration.properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet

            $vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri | ? ResourceId -Match  $TenantVM.Tenant

            if ( $null -eq $vnet) { throw "Issue getting Vnet for Tenant=$($TenantVM.Tenant)" }

            $ipconfiguration.properties.subnet.ResourceRef = $vnet.Properties.Subnets[0].ResourceRef

            $vmnicproperties.IpConfigurations = @($ipconfiguration)

            Write-SDNNestedLog  "Pushing  $($TenantVM.Name) NIC config to REST API"

            $nic = New-NetworkControllerNetworkInterface -ResourceID $vmnicResourceId -Properties $vmnicproperties -ConnectionUri $uri -Force
        }
         
        Invoke-Command -ComputerName $TenantVM.HypvHostname {
            $TenantVM = $args[0]
            $uri = $args[1]
            $cred = $args[2]

            if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested\utils\SDNNested-Module.psm1 }

            #Do not change the hardcoded IDs in this section, because they are fixed values and must not change.
            $FeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
                                
            $vmNics = Get-VMNetworkAdapter -VMName $TenantVM.Name
                                
            $CurrentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $FeatureId -VMNetworkAdapter $vmNics 

           Write-SDNNestedLog  "Configuring SDNSwith Extension for $($TenantVM.Name) vNIC"
            
            $nic = Get-NetworkControllerNetworkInterface -ResourceID "$($TenantVM.Name)_VMNIC0" -ConnectionUri $uri 
            
            if ($null -eq $CurrentFeature) {
                $Feature = Get-VMSystemSwitchExtensionPortFeature -FeatureId $FeatureId

                $Feature.SettingData.ProfileId = "{$($nic.InstanceId)}"
                $Feature.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
                $Feature.SettingData.CdnLabelString = "TestCdn"
                $Feature.SettingData.CdnLabelId = 1111
                $Feature.SettingData.ProfileName = "Testprofile"
                $Feature.SettingData.VendorId = "{1FA41B39-B444-4E43-B35A-E1F7985FD548}"
                $Feature.SettingData.VendorName = "NetworkController"
                $Feature.SettingData.ProfileData = 1
                            
                Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $Feature -VMNetworkAdapter $vmNics 
            }
            else {
                $CurrentFeature.SettingData.ProfileId = "{$($nic.InstanceId)}"
                $CurrentFeature.SettingData.ProfileData = 1
                        
                Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $CurrentFeature -VMNetworkAdapter $vmNics
            }
            #Wait to be sure that Mac Address Allocation has been done
            do{
                $nic = Get-NetworkControllerNetworkInterface -ResourceID $nic.resourceid -ConnectionUri $uri
                Start-Sleep 1
            }while ( $null -eq $nic.properties.PrivateMacAddress );

            $vmNics | Set-VMNetworkAdapter -StaticMacAddress $nic.properties.PrivateMacAddress   
            
            Write-SDNNestedLog "Starting VM $($TenantVM.Name)"
            Start-VM $TenantVM.Name
            WaitLocalVMisBooted $TenantVM.Name $cred
        } -ArgumentList $TenantVM, $uri, $cred
            
        if ( $TenantVM.roles -eq "ContainerHost") 
        {
            $FirstIpInPool =   $($TenantVM.ContainersIpPool).split("/")[0]
            $LastIpInPool = Get-IPLastAddressInSubnet $TenantVM.ContainersIpPool

            $NbrIP =  $LastIpInPool.split(".")[-1] - $FirstIpInPool.split(".")[-1] 

            $ip=$FirstIpInPool
            $ContainersIPs = @()
            for( $i=0; $i -lt $NbrIP; $i++)
            {
                $ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
                $ipconfiguration.resourceid = "$($TenantVM.Name)_IP$($i+1)"
                $ipconfiguration.properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
                $ipconfiguration.properties.PrivateIPAddress = $ip
                $ipconfiguration.properties.PrivateIPAllocationMethod = "Static"
                $ipconfiguration.properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
                $ipconfiguration.properties.subnet.ResourceRef = $vnet.Properties.Subnets[0].ResourceRef
    
                $nic.properties.IpConfigurations += $ipconfiguration

                $ContainersIPs += $ip 

                [int]$LastByte = $ip.split(".")[-1]
                $LastByte++
                $ip = "$($ip.split(".")[0])" + "."  + "$($ip.split(".")[1])" + "." + "$($ip.split(".")[2])" + "."  + "$LastByte"
            }

            Write-SDNNestedLog "Adding ContainerIpPool=$($TenantVM.ContainersIpPool) to $($TenantVM.Name) VMNic Object"
            $nic = New-NetworkControllerNetworkInterface -ResourceID $nic.resourceid -Properties $nic.properties -ConnectionUri $uri -Force

            $LB = $ConfigData.SlbVIPs | ? Tenant -eq $TenantVM.Tenant

            Invoke-Command -ComputerName $TenantVM.HypvHostname {
                $ContainersIPs = $args[0]
                $TenantVM = $args[1]
                $cred = $args[2]
                $LB = $args[3]

                $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")
                #Session ID Dec:999 is System one 
                $WMIdrive = (Get-WmiObject -Class Win32_MappedLogicalDisk | ? ProviderName -Match $LocalVMName | ? sessionId -ne 999)[-1]

                if ( ! $WMIdrive ){
                    $UNCprefix = "\\$LocalVMName\Template"
                }
                else {
                    $UNCprefix = $($WMIdrive.Name)
                }

                if ( ! ( Test-Path $UNCprefix)  )
                {
                    Write-SDNNestedLog "FAILED: DEPLOYMENT STOPPED. $env:computername CANNOT ACCESS THE SHARE \\$LocalVMName\Template / $UNCprefix. Please map the drive again"
                    throw "FAILED: DEPLOYMENT STOPPED. $env:computername CANNOT ACCESS THE SHARE \\$LocalVMName\Template / $UNCprefix. Please map the drive again"
                }

                if ( ! (Get-Module SDNNested-Module ) ){ import-module $UNCprefix\SDNNested\utils\SDNNested-Module.psm1 }

                $pssession = New-PSSession -VMName $TenantVM.Name -Credential $cred     
                if ( $pssession )
                {
                    Write-SDNNestedLog "Sync needed scripts to ContainerHost $($TenantVM.Name)"
                    copy-item -ToSession $pssession -Destination C:\temp -Path $UNCprefix\SDNNested\utils\Container\ -Recurse -force
                }
                else
                {
                    Write-SDNNestedLog "FAILED: DEPLOYMENT STOPPED. $env:computername CANNOT ACCESS  $($TenantVM.Name) from PS"
                    throw "FAILED: DEPLOYMENT STOPPED. $env:computername CANNOT ACCESS  $($TenantVM.Name) from PS"
                }

                Invoke-Command -VMName $TenantVM.Name -Credential $cred {
                    #Checking docker service status
                    $ContainersIPs = $args[0]
                    $LB = $args[1]

                    get-service docker |  %{ if($_.Status -ne "Running"){ Start-Service docker} }
                    cd c:\temp 
                    
                    Write-Host "Creating docker custom IIS container image from docker file iis-site"
                    docker build -f C:\temp\iis-site -t iis-site . 
                    
                    Write-Host "Creating docker l2bridge network"
                    
                    $NetIPAddr = Get-NetAdapter Ethernet | Get-NetIPAddress -AddressFamily IPv4 | select IPAddress,PrefixLength,ifIndex
                    $subnet = (Get-NetRoute -ifIndex $($NetIPAddr.ifIndex) | ? DestinationPrefix -match "/$($NetIPAddr.PrefixLength)").DestinationPrefix
                    $NextHop = (Get-NetIPConfiguration -ifIndex $NetIPAddr.ifIndex).IPv4DefaultGateway.nexthop

                    docker network create -d l2bridge -o com.docker.network.windowsshim.interface="Ethernet" --subnet="$subnet" `
                        --gateway="$NextHop" Myl2bridgeNetwork

                    Write-Host  "Running $($ContainersIPs.count) containers"
                    foreach ( $IP in $ContainersIPs)
                    {
                        docker run -d --restart always --network=Myl2bridgeNetwork --ip="$IP" -v C:\temp\:C:\temp `
                            -e CONTAINER_HOST=$($env:computername) iis-site powershell C:\temp\GenIISDefault.ps1          
                    }

                    if( Test-Path c:\temp\HNS.V2.psm1 )
                    {
                        import-module c:\temp\HNS.V2.psm1

                        #$VIP=(Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -Match "172.16.1.").IPAddress
                        $VIP = $NetIPAddr.IPAddress
                        $endpoints = Get-HnsEndpoint
                        Write-Host  "Creating LoadBalancer on ContainerHost $env:computername  using HNVv2 API - use VFPCTRL tool to check NAT rules"
                        
                        $protocol = if ( $LB.protocol -eq "TCP") { 6 }elseif($LB.protocol -eq "UDP"){ 17 }
                        
                        New-HnsLoadBalancer -InternalPort $LB.FrontendPort -ExternalPort $LB.BackendPort -Endpoints $endpoints.Id -Protocol $Protocol -Vip $VIP -DSR
                    }
                    else 
                    {
                        Write-Host -ForegroundColor Red "Creating LoadBalancer on ContainerHost $env:computername failed. LB to Public VIP will failed"
                    }
                } -ArgumentList $ContainersIPs, $LB
            } -ArgumentList $ContainersIPs, $TenantVM, $cred, $LB
        }
        else 
        {
            Write-SDNNestedLog   "Adding required features on VM $($TenantVM.Name)"
            
            Invoke-Command -ComputerName $TenantVM.HypvHostname {
                $TenantVM = $args[0]
                $cred = $args[1]

                if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested\utils\SDNNested-Module.psm1 }

                Add-WindowsFeatureOnVM $TenantVM.Name $cred $TenantVM.Roles

                Invoke-Command -VMName $TenantVM.Name -Credential $cred {
                    $colors = @("red", "blue", "green", "yellow", "purple", "orange", "pink", "gray")
                    $index = Get-Random -Minimum 0 -Maximum 8
                    mv C:\inetpub\wwwroot\iisstart.htm C:\inetpub\wwwroot\iisstart.htm.old -Force
                    $background = $colors[$index]
                    
                    $ip=((Get-NetIPAddress -AddressFamily IPv4).IPAddress)[0]

                    $content = @"
<html>
<body bgcolor="$background">
<h1>VMName:$env:computername</h1>
<h1>VMip:$ip</h1>
</body>
</html>
"@
                    Add-Content -Path C:\inetpub\wwwroot\iisstart.htm $content
                }
                <#
                if( (Get-VM $TenantVM.Name | Get-VMHardDiskDrive).Path -match "clusterStorage" ){ 
                    Write-SDNNestedLog   "Move VM=$($TenantVM.Name) to the node configured"                
                    Get-VM $TenantVM.Name | Move-ClusterVirtualMachineRole -Node $TenantVM.HypvHostname -ErrorAction SilentlyContinue
                } 
                #>
            } -ArgumentList $TenantVM, $cred
        }

    }
    else {
       Write-SDNNestedLog  "VM $($TenantVM.Name) already exist on $($vm.computername)"
    }
}

foreach ($vip in $configdata.SlbVIPs) 
{
    $vipLogicalNetwork = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri -ResourceId "PublicVIP"
    $LoadBalancerProperties = new-object Microsoft.Windows.NetworkController.LoadBalancerProperties

    $lbresourceId = "LB_$($vip.Tenant)_$($vip.VIP.Replace('.','_'))"
    # Create a front-end IP configuration

    $FrontEnd = new-object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfiguration
            
    $FrontEnd.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfigurationProperties
    $FrontEnd.resourceId = "$($vip.Tenant)-FE1"
    $FrontEnd.ResourceRef = "/loadBalancers/$lbresourceId/frontendIPConfigurations/$($FrontEnd.ResourceId)"
    $FrontEnd.properties.PrivateIPAddress = $vip.VIP
    $FrontEnd.Properties.PrivateIPAllocationMethod = $vip.VIPAllocationMethod
    $FrontEnd.Properties.Subnet = @{}
    $FrontEnd.Properties.Subnet.ResourceRef = $vipLogicalNetwork.Properties.Subnets[0].ResourceRef
    $LoadBalancerProperties.frontendipconfigurations += $FrontEnd

    # Create a back-end address pool

    $BackEnd = new-object Microsoft.Windows.NetworkController.LoadBalancerBackendAddressPool
    $BackEnd.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerBackendAddressPoolProperties
    $BackEnd.resourceId = "$($vip.Tenant)-BE1"
    $BackEnd.ResourceRef = "/loadBalancers/$lbresourceId/backendAddressPools/$($BackEnd.ResourceId)"
            
    $LoadBalancerProperties.backendAddressPools += $BackEnd

    # Create the Load Balancing Rules
    $LoadBalancerProperties.loadbalancingRules += $lbrule = new-object Microsoft.Windows.NetworkController.LoadBalancingRule
    $lbrule.properties = new-object Microsoft.Windows.NetworkController.LoadBalancingRuleProperties
    $lbrule.ResourceId = "$($vip.Tenant)-WebRainbow"
    $lbrule.properties.frontendipconfigurations += $FrontEnd
    $lbrule.properties.backendaddresspool = $BackEnd 
    $lbrule.properties.protocol = $vip.Protocol
    $lbrule.properties.frontendPort = $vip.FrontendPort
    $lbrule.properties.backendPort = $vip.BackendPort
    $lbrule.properties.IdleTimeoutInMinutes = 4

    
    $Probe = new-object Microsoft.Windows.NetworkController.LoadBalancerProbe
    $Probe.ResourceId = "Probe1"
    $Probe.ResourceRef = "/loadBalancers/$lbresourceId/Probes/$($Probe.ResourceId)"
   
    $Probe.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerProbeProperties
    $Probe.properties.Protocol = $vip.Protocol
    $Probe.properties.Port = $vip.BackendPort
    #$Probe.properties.RequestPath = "/health.htm"
    $Probe.properties.IntervalInSeconds = 5
    $Probe.properties.NumberOfProbes = 3
   
    $LoadBalancerProperties.Probes += $Probe

    $LoadBalancerProperties.loadbalancingRules.properties.Probe += $Probe 

    Write-SDNNestedLog  "Pushing LoadBalancer $lbresourceId to $uri"
    $lb = New-NetworkControllerLoadBalancer -ConnectionUri $uri -ResourceId $lbresourceId `
        -Properties $LoadBalancerProperties -Force -PassInnerException

    foreach ($vm in $vip.TenantVMs) {
        $nic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri -ResourceId "$($vm)_VMNIC0"
        if ($nic) 
        {
            $nic.Properties.IpConfigurations[0].Properties.LoadBalancerBackendAddressPools = $lb.Properties.BackendAddressPools[0]
            Write-SDNNestedLog   "Adding NIC ipconfig to LB backend address pool"
            New-NetworkControllerNetworkInterface -ResourceId $nic.ResourceId -Properties $nic.Properties `
                -ConnectionUri $uri -Force 
        }
        else {
           Write-SDNNestedLog  "SLB: Failed to add $vm NIC to the VIP BackendAddressPools. NetworkControllerNetworkInterface does not exist for $vm. "
        }
    }
}

#Fixing GRE and BGP peering on Tenants "physical" gateways
winrm set winrm/config/client '@{TrustedHosts="*"}'

try{
    $configdataInfra = [hashtable] (iex (gc .\configFiles\$($configdata.ConfigFileName)\SDNNested-Deploy-Infra.psd1 | out-string))
}catch {} 

if ($configdataInfra.VMHostPwd){
    $secpasswd = ConvertTo-SecureString $configdataInfra.VMHostPwd -AsPlainText -Force
    $AzCred = New-Object System.Management.Automation.PSCredential($configdataInfra.VMHostadmin,$secpasswd)
}else{
    $AzCred = Get-Credential $configdataInfra.VMHostadmin
}

$LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")

foreach( $Tenant in $configdata.Tenants) 
{ 
    $PhysicalGwVMName = $Tenant.PhysicalGwVMName

    $vgw = Get-NetworkControllerVirtualGateway -ConnectionUri $uri | ? ResourceId -Match $Tenant.Name
    
    if ( $vgw.Properties.NetworkConnections.properties.ConnectionType -eq "GRE" ) 
    {
        $GreDestination = $vgw.Properties.NetworkConnections.properties.SourceIPAddress

       Write-SDNNestedLog  "Fixing GRE tunnel peer on 'physical' $PhysicalGwVMName"
        if ( $GreDestination)
        {
            Invoke-Command -Computername $LocalVMName  -Credential $AzCred {
                $cred=$args[0]
                $PhysicalGwVMName=$args[1]
                $GreDestination=$args[2]
                Invoke-Command  -VMName $PhysicalGwVMName -Credential $cred {
                    $GreDestination=$args[0]
                    Get-VpnS2SInterface | Set-VpnS2SInterface -GreTunnel -AdminStatus $false -force
                    Get-VpnS2SInterface | Set-VpnS2SInterface -GreTunnel -Destination $GreDestination
                    Get-VpnS2SInterface | Set-VpnS2SInterface -GreTunnel -AdminStatus $true
                } -ArgumentList $GreDestination

            } -ArgumentList $LocalAdminCredential, $PhysicalGwVMName, $GreDestination
        }
    }

    $BgpPeer = $vgw.Properties.BgpRouters.Properties.RouterIP

    if( $BgpPeer)
    {
       Write-SDNNestedLog  "Fixing BGP Peering configuration tunnel peer on 'physical' $($Tenant.PhysicalGwVMName)"
        Invoke-Command  -Computername $LocalVMName -Credential $AzCred { 
            $cred=$args[0]
            $PhysicalGwVMName=$args[1]
            $BgpPeer=$args[2]

            Invoke-Command -VMName $PhysicalGwVMName -Credential $cred {
                $BgpPeer=$args[0]
                Get-BgpPeer | Set-BgpPeer -PeerIpAddress $BgpPeer -force
                $LocalBgpIP = (Get-BgpPeer).LocalIPAddress
                
                if( $null -eq (Get-NetIPAddress | ? IPAddress -Match $LocalBgpIP))
                {
                    Get-NetAdapter | New-NetIPAddress -IPAddress $LocalBgpIP -PrefixLength 24
                } 

            } -ArgumentList $BgpPeer
    
        } -ArgumentList $LocalAdminCredential, $PhysicalGwVMName, $BgpPeer
    }

}