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


Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Adding Tenant to SDN through Northbound API "
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
#Find the Access Control List to user per virtual subnet  
#$acllist = Get-NetworkControllerAccessControlList -ConnectionUri $uri -ResourceId "AllowAll"  
#Find the HNV Provider Logical Network  
$HNVProviderLogicalNetwork = Get-HNVProviderLogicalNetwork $uri 

foreach ($Tenant in $configdata.Tenants) 
{
    $vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri | ? ResourceId -eq $Tenant.TenantVirtualNetworkName 
    if ( ! $vnet )
    {
        $vnet = New-TenantVirtualNetwork $uri $Tenant $HNVProviderLogicalNetwork 
    }
    $vnet  

    $gwpool = Get-SDNGatewayPool $uri

    foreach ($Gw in $configdata.TenantvGWs) 
    {    
        if ( $Gw.Tenant -eq $Tenant.Name) 
        { 
            $VirtualGW = Get-NetworkControllerVirtualGateway -ConnectionUri $uri | ? ResourceId -eq $Gw.VirtualGwName
            if ( $VirtualGW )
            {
                Write-SDNNestedLog "$($Gw.VirtualGwName) is already existing so delete it before!"
                Remove-NetworkControllerVirtualGateway -ConnectionUri $uri -ResourceId $Gw.VirtualGwName -force
            }
            $VirtualGW = New-SDNVirtualGateway $uri "$($Gw.VirtualGwName)" $Tenant $vnet "vGW" $gwpool $HNVProviderLogicalNetwork

            $VirtualGW

            New-SDNVirtualGatewayNetworkConnections $uri $gw $virtualGW.ResourceId

            $bgpRouterId = New-SDNVirtualGatewayBgpRouter $uri $gw $virtualGW.ResourceId

            if ( $bgpRouterId )
            {
                New-SDNVirtualGatewayBgpPeer $uri $gw $bgpRouterId $virtualGW.ResourceId
            }
        }
    }
}

Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Creating Tenant's VMs"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
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
            
            if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested*\utils\SDNNested-Module.psm1 }

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

        $cpt=0;
        #Creating NIC object on NCs
        foreach ( $NIC in $TenantVM.NICs) 
        {

            $vnet = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri | ? ResourceId -Match  $TenantVM.Tenant

            if ( $null -eq $vnet) { throw "Issue getting Vnet for Tenant=$($TenantVM.Tenant)" }
            
            for( $i=0;$i -lt $Vnet.Properties.Subnets.count; $i++ )
            {
                if (  $Vnet.Properties.Subnets[$i] | ? ResourceId -eq $TenantVM.Subnet )
                {
                    $TenantSubnetRef = $Vnet.Properties.Subnets[$i].ResourceRef
                }
            }
            $vmnicResourceId = "$($TenantVM.Name)_NIC$cpt"

            $nic = New-SDNNetworkInterface $uri $vmnicResourceId $NIC $TenantSubnetRef
            $cpt++
        }
     
        Invoke-Command -ComputerName $TenantVM.HypvHostname {
            $TenantVM = $args[0]
            $uri = $args[1]
            $cred = $args[2]

            if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested*\utils\SDNNested-Module.psm1 }

            $SDNNic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri | ? ResourceID -match $TenantVM.Name

            Connect-SDNNetworkInterface $uri $TenantVM.Name $SDNNic.resourceId $SDNNic.InstanceId
                 
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
<#
                $ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
                $ipconfiguration.resourceid = "$($TenantVM.Name)_IP$($i+1)"
                $ipconfiguration.properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
                $ipconfiguration.properties.PrivateIPAddress = $ip
                $ipconfiguration.properties.PrivateIPAllocationMethod = "Static"
                $ipconfiguration.properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
                $ipconfiguration.properties.subnet.ResourceRef = $TenantSubnetRef
    
                $nic.properties.IpConfigurations += $ipconfiguration
#>
                Add-SDNNetworkInterfaceIPConfiguration $uri "$($TenantVM.Name)_IP$($i+1)" $ip $TenantSubnetRef $SDNNic

                $ContainersIPs += $ip 

                [int]$LastByte = $ip.split(".")[-1]
                $LastByte++
                $ip = "$($ip.split(".")[0])" + "."  + "$($ip.split(".")[1])" + "." + "$($ip.split(".")[2])" + "."  + "$LastByte"
            }

            #Write-SDNNestedLog "Adding ContainerIpPool=$($TenantVM.ContainersIpPool) to $($TenantVM.Name) VMNic Object"
            #$nic = New-NetworkControllerNetworkInterface -ResourceID $nic.resourceid -Properties $nic.properties -ConnectionUri $uri -Force

            $LB = $ConfigData.SlbVIPs | ? Tenant -eq $TenantVM.Tenant

            Invoke-Command -ComputerName $TenantVM.HypvHostname {
                $ContainersIPs = $args[0]
                $TenantVM = $args[1]
                $cred = $args[2]
                $LB = $args[3]


                $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")

                $UNCprefix = "\\$LocalVMName\Template"
                #Session ID Dec:999 is System one 
                $WMIdrive = (Get-WmiObject -Class Win32_MappedLogicalDisk | ? ProviderName -Match $LocalVMName | ? sessionId -ne 999)

                if ( ! $WMIdrive )
                {
                    $UNCprefix = "\\$LocalVMName\Template"
                }
                else 
                {
                    if ( $WMIdrive.count ){ $WMIdrive = $WMIdrive[-1] }
                    $UNCprefix = $($WMIdrive.Name)
                }
                #>

                if ( ! ( Test-Path $UNCprefix)  )
                {
                    throw "FAILED: DEPLOYMENT STOPPED. $env:computername CANNOT ACCESS THE SHARE \\$LocalVMName\Template / $UNCprefix. Please map the drive again"
                }

                if ( ! (Get-Module SDNNested-Module ) ){ import-module $UNCprefix\SDNNested*\utils\SDNNested-Module.psm1 }

                $pssession = New-PSSession -VMName $TenantVM.Name -Credential $cred     
                if ( $pssession )
                {
                    Write-SDNNestedLog "Sync needed scripts to ContainerHost $($TenantVM.Name)"
                    copy-item -ToSession $pssession -Destination C:\temp -Path $UNCprefix\SDNNested*\utils\Container\ -Recurse -force
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

                if ( ! (Get-Module SDNNested-Module ) ){ import-module Z:\SDNNested*\utils\SDNNested-Module.psm1 }

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


Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Configuring SLB Tenant's VIP"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
$vipLogicalNetwork = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri -ResourceId "PublicVIP"

foreach ($vip in $configdata.SlbVIPs) 
{
    $LBResourceId       = "LB_$($vip.Tenant)_$($vip.VIP.Replace('.','_'))"
    $lb = Get-NetworkControllerLoadBalancer -ConnectionUri $uri | ? ResourceId -eq $LBResourceId 
    if( $lb )
    {
        Write-SDNNestedLog "LB: Removing $LBResourId LB oject before creating it again"
        Remove-NetworkControllerLoadBalancer -ConnectionUri $uri -ResourceId $lb.resourceid -force
    }
    #$lb = New-SDNSoftwareLoadBalancer $uri $lbresourceId $null $null $null $null $null 

    $VIPAllocationMethod= $vip.VIPAllocationMethod
    $FrontendSubnetRef  = $vipLogicalNetwork.Properties.Subnets[0].ResourceRef
  
    # Create a front-end IP configuration
    $FrontEndResourceId = "LB-FE1"
    $Frontend = New-SDNSoftwareLoadBalancerFrontendIpConfiguration $uri $vip.VIP $LBResourceId `
                    $FrontEndResourceId $VIPAllocationMethod $FrontendSubnetRef
       
    # Create a back-end address pool
    $BackEndResourceId = "LB-BE1"
    $BackEndPool = New-SDNSoftwareLoadBalancerBackendAddressPool $uri $LBResourceId $BackEndResourceId
    
    # Create the Load Balancing Rules
    $LBRuleResourceId   = "LBRULE-$($vip.Tenant)-WebRainbow"
    $lbrule = New-SDNLoadBalancingRule $LBRuleResourceId $FrontEnd $BackEndPool $vip
    $Probe = New-SDNLoadBalancerProbe "Probe1" $LBResourceId $vip 5 3
    $onatrule = $null

    $lb = New-SDNSoftwareLoadBalancer $uri $LBResourceId $frontend $backendpool $lbrule $onatrule $Probe 

    #Printing LB object
    $lb 
    
    foreach ($vm in $vip.TenantVMs) 
    {
        $nic = Get-NetworkControllerNetworkInterface -ConnectionUri $uri | ? ResourceId -match $vm
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

Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Outbound NAT for tenant VM's"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"
$vipLogicalNetwork = get-networkcontrollerlogicalnetwork -ConnectionUri $uri -resourceid "PublicVIP" -PassInnerException
#Removing LB oject if it is existing
$LBResourceId       = "LB_$($configdata.OutboundNAT[0].Name)"
$lb = Get-NetworkControllerLoadBalancer -ConnectionUri $uri | ? ResourceId -eq $LBResourceId 
if( $lb )
{
    Write-SDNNestedLog "LB: Removing $LBResourId LB oject before creating it again"
    Remove-NetworkControllerLoadBalancer -ConnectionUri $uri -ResourceId $lb.resourceid -force
}

foreach ( $ONAT in $configdata.OutboundNAT )
{
    $VIPAllocationMethod= $ONAT.VIPAllocationMethod
    $FrontendSubnetRef  = $vipLogicalNetwork.Properties.Subnets[0].ResourceRef
  
    # Create a front-end IP configuration
    $FrontEndResourceId = "ONAT-$($ONAT.Tenant)-FE1"
    $Frontend = New-SDNSoftwareLoadBalancerFrontendIpConfiguration $uri $ONAT.VIP $LBResourceId `
                    $FrontEndResourceId $VIPAllocationMethod $FrontendSubnetRef
       
    # Create a back-end address pool
    $BackEndResourceId = "ONAT-$($ONAT.Tenant)-BE1"
    $BackEndPool = New-SDNSoftwareLoadBalancerBackendAddressPool $uri $LBResourceId $BackEndResourceId
    
    $probe = $null
    $lbrule = $null
  
    $LBRuleResourceId   = "LBRULE-$($ONAT.Tenant)-onat1"
    $Protocol           = "ALL"
    $onatrule = New-SDNLoadBalancerOutboundNatRule $LBRuleResourceId $FrontEnd $BackEndPool $Protocol

    $onatlb = New-SDNSoftwareLoadBalancer $uri $LBResourceId $Frontend $BackEndPool $lbrule $onatrule $probe 
}
#Printing LB object
$onatlb 

foreach ( $Tenant in $configdata.OutboundNAT )
{
    $NICs = Get-NetworkControllerNetworkInterface -ConnectionUri $uri | ? ResourceId -Match $Tenant.Tenant
    foreach ( $NIC in $NICs)
    {
        $NIC.properties.IpConfigurations[0].properties.LoadBalancerBackendAddressPools += $onatlb.properties.backendaddresspools | ? ResourceId -Match $Tenant.Tenant
        new-networkcontrollernetworkinterface  -connectionuri $uri -resourceid $NIC.resourceId -Properties $NIC.properties -force -PassInnerException
    }
}
    
#Fixing GRE and BGP peering on Tenants 
Write-SDNNestedLog "############"
Write-SDNNestedLog "########"
Write-SDNNestedLog "####"
Write-SDNNestedLog "### Configuring external TENANTs GWs"
Write-SDNNestedLog "####"
Write-SDNNestedLog "########"
Write-SDNNestedLog "############"

#Fixing GRE and BGP peering on Tenants "physical" gateways
winrm set winrm/config/client '@{TrustedHosts="*"}' | Out-Null

try{
    $configdataInfra = [hashtable] (iex (gc .\configFiles\$($configdata.ConfigFileName)\SDNNested-Deploy-Infra.psd1 | out-string))
}catch {} 

#Getting VMHost (LocalVM) credential
if ( $configdataInfra.VMHostadmin -and $configdataInfra.VMHostPwd) 
{
    $secpasswd = ConvertTo-SecureString $configdataInfra.VMHostPwd -AsPlainText -Force
    $VMHostCred = New-Object System.Management.Automation.PSCredential ($configdataInfra.VMHostadmin, $secpasswd)
}
else 
{
    $account = (get-localuser | ? Description -Match "Built-in account for administraring").name
    $Msg = "Please enter Host=$env:ComputerName account=$account "
    $VMHostCred = (Get-Credential -Message $Msg -Credential $account)   
}


$LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")

Write-SDNNestedLog  "Checking if external tenants GWs are UP!"
#
#   Checking whether all Tenant's external GWs are UP or not! If down, VM is going to be started!  
#
Invoke-Command  -Computername $LocalVMName -Credential $VMHostCred { 
    $VMs = $args[0]
    $LocalAdminCredential = $args[1]

    foreach ( $vm in $VMs)
    {
        $state = (get-vm $vm).state
        if ( $state -ne "Running" )
        {
            Write-Host "$vm : is not running so starting it!"
            start-vm $vm

            Write-Host "$vm : waiting the VM to be ready"
            while ((Invoke-Command -VMName $vm -Credential $LocalAdminCredential { $env:COMPUTERNAME } `
            -ea SilentlyContinue) -ne $vm) { Start-Sleep -Seconds 1 }
            Write-Host "$vm : is ready"
        }
    }
} -ArgumentList $configdata.Tenants.PhysicalGwVMName, $LocalAdminCredential

#
#   At this stage, all Tenant's external GWs shoulb be UP ! 
#
foreach( $Tenant in $configdata.Tenants) 
{ 
    $PhysicalGwVMName = $Tenant.PhysicalGwVMName

    $vgw    = Get-NetworkControllerVirtualGateway -ConnectionUri $uri | ? ResourceId -Match $Tenant.Name
    $vnet   = Get-NetworkControllerVirtualNetwork -ConnectionUri $uri | ? ResourceId -Match $Tenant.Name

    if ( ! $vgw )
    {
        throw "Failed to configure Tenant's external GWs as vGW object cannot retrieve via Northbound API!"
    }
    elseif ( ! $vnet )
    {
        throw "Failed to configure Tenant's external GWs as vNET object cannot retrieve via Northbound API!"
    }
    
    Write-SDNNestedLog "--> Staging $PhysicalGwVMName"
    Invoke-Command -Computername $LocalVMName -Credential $VMHostCred {
        $cred=$args[0]
        $PhysicalGwVMName=$args[1]
        $vgw=$args[2]
        $vnet=$args[3]
        $vTenantvGWs=$args[4]
        #
        Invoke-Command  -VMName $PhysicalGwVMName -Credential $cred {
            $vgw    = $args[0] | ConvertFrom-Json
            $vnet   = $args[1] | ConvertFrom-Json
            $vTenantvGWs=$args[2]

            $ConnectionType =  $vgw.Properties.NetworkConnections.properties.ConnectionType
            $RemoteNetwork = $vnet.Properties.AddressSpace.AddressPrefixes

            $IntAlias = "Ethernet"
            
            #InstallLoopback
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            Install-Module -Name LoopbackAdapter -MinimumVersion 1.2.0.0 -Force | Out-Null
            Import-Module -Name LoopbackAdapter 

            $run = (Get-Service RemoteAccess).status
            Set-Service RemoteAccess -StartupType Automatic
            if ( $run -ne "Running") { Start-Service RemoteAccess }

            $tunnelMode = $false                   
            if ( $ConnectionType -eq "L3" )
            {
                $VpnType = "RoutingOnly"    
            }
            elseif ( $ConnectionType -eq "GRE" -or $ConnectionType -eq "IPSEC" )
            {
                $VpnType = "VpnS2S"   
                $tunnelMode = $true                                    
            }                    
            $RemoteAccessStatus = Get-RemoteAccess
            if ( $ConnectionType -eq "L3" )
            {
                if(  $RemoteAccessStatus.RoutingStatus -ne "Installed")
                {
                    Write-Host "Installing Remote Access VPNtype=$VpnType on $env:COMPUTERNAME"
                    Install-RemoteAccess -VpnType $VpnType
                }
            }
            elseif ( $ConnectionType -eq "GRE" -or $ConnectionType -eq "IPSEC" )
            {
                if(  $RemoteAccessStatus.VpnS2SStatus -ne "Installed")
                {
                    Write-Host "Installing Remote Access VPNtype=$VpnType on $env:COMPUTERNAME"
                    Install-RemoteAccess -VpnType $VpnType
                }  
            }

            #Configuring GW
            if ( $tunnelMode ) 
            {
                $tunnelAdapter=$ConnectionType+"_LocalPeer" 
                
                if ( !(Get-NetAdapter $tunnelAdapter -ea SilentlyContinue) )
                {
                    New-LoopbackAdapter -Name $tunnelAdapter -Force | Out-Null
                }
                Write-Host "Configuring $($TenantvGW.Type) tunnel on $env:COMPUTERNAME"

                $LocalPeer = $vgw.Properties.NetworkConnections.properties.DestinationIPAddress 
                $DestinationPeer = $vgw.Properties.NetworkConnections.properties.SourceIPAddress 

                #Checking if GrePeer is plumbed 
                if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $LocalPeer) ) { 
                    Write-Host  "IP Address $LocalPeer is missing so adding it"
                    Get-NetAdapter $tunnelAdapter | New-NetIPAddress -IPAddress $LocalPeer -PrefixLength 32 | Out-Null
                }
                                    
                if ( $ConnectionType -eq "GRE") 
                {
                    $PSK = $vgw.Properties.NetworkConnections.properties.GreConfiguration.GreKey

                    Add-VpnS2SInterface -Name $ConnectionType -Destination $DestinationPeer -SourceIpAddress $LocalPeer -GreKey $PSK `
                        -GreTunnel -IPv4Subnet "$($RemoteNetwork):10"
                }
                elseif ( $ConnectionType -eq "IPSEC" )
                {
                    $PSK = ($vTenantvGWs | ? VirtualGwName -eq $vgw.resourceId | ? Type -eq $ConnectionType).PSK
                    
                    $PerfectForwardSecrecy = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy   
                    $AuthenticationTransformationConstant = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant    
                    $CipherTransformationConstant = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.CipherTransformationConstant
                    $SALifeTimeSeconds = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.SALifeTimeSeconds
                    $IdleDisconnectSeconds = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds   
                    $SALifeTimeKiloBytes = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes
                    
                    $DiffieHellmanGroup = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.MainMode.DiffieHellmanGroup   
                    $IntegrityAlgorithm = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.MainMode.IntegrityAlgorithm   
                    $EncryptionAlgorithm = $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.MainMode.EncryptionAlgorithm   

                    if (  $vgw.Properties.NetworkConnections.properties.IpSecConfiguration.AuthenticationMethod -eq "PSK")
                    {
                        $AuthenticationMethod = "PSKOnly" 
                    }
                    Add-VpnS2SInterface -CustomPolicy -Name $ConnectionType -Destination $DestinationPeer -SourceIpAddress $LocalPeer `
                        -EncryptionMethod $EncryptionAlgorithm -DhGroup $DiffieHellmanGroup  -PfsGroup $PerfectForwardSecrecy `
                        -CipherTransformConstants $CipherTransformationConstant  -IntegrityCheckMethod $IntegrityAlgorithm `
                        -AuthenticationTransformConstants $AuthenticationTransformationConstant -Protocol "IKEv2" `
                        -AuthenticationMethod $AuthenticationMethod -SharedSecret $PSK -SALifeTimeSeconds $SALifeTimeSeconds `
                        -IdleDisconnectSeconds $IdleDisconnectSeconds -SADataSizeForRenegotiationKilobytes $SALifeTimeKiloBytes `
                        -IPv4Subnet "$($RemoteNetwork):10"
                }
            }

            #BgpConfig
            $BgpPeerId      = $vgw.Properties.BgpRouters.ResourceId  
            $BgpRouterId    = $vgw.Properties.bgprouters.properties.BgpPeers.ResourceId
            
            if ( $BgpPeerId )
            {
                Write-Host "Configuring BGP router on $env:COMPUTERNAME"
                $BgpLocalIp     = $vgw.Properties.BgpRouters.properties.BgpPeers.properties.PeerIpAddress
                $BgpLocalExtAs  = $vgw.Properties.BgpRouters.properties.BgpPeers.properties.ExtAsNumber
                $BgpLocalAs     = $BgpLocalExtAs.split(".")[-1] 

                $BgpPeerIp      = $vgw.Properties.BgpRouters.properties.RouterIP[0]
                $BgpPeerId      = $vgw.Properties.BgpRouters.ResourceId
                $BgpPeerExtAs   = $vgw.Properties.BgpRouters.properties.ExtAsNumber
                $BgpPeerAs      = $BgpPeerExtAs.split(".")[-1] 

                if ( $ConnectionType -eq "L3" )
                {
                    $GW = $vgw.Properties.NetworkConnections.properties.IPAddresses[0].IPAddress
                    Write-Host "Add NEtRoute to PeerIp=$BgpPeerIp NExthop=$GW Int=$Intalias on $env:COMPUTERNAME"
                    New-NetRoute -DestinationPrefix "$BgpPeerIp/32" -NextHop $GW -interfaceAlias $IntAlias | Out-Null
                }
                <#
                else
                {
                    $LocalIp=(Get-NetAdapter $IntAlias | Get-NetIpAddress -AddressFamily IPv4).IPAddress    
                    $GW = $LocalIp.split(".")[0]+"."+$LocalIp.split(".")[1]+"."+$LocalIp.split(".")[2]+".1"
                    Write-Host "Add NEtRoute to PeerIp=$BgpPeerIp NExthop=$GW Int=$Intalias on $env:COMPUTERNAME"
                    New-NetRoute -DestinationPrefix "$DestinationPeer/32" -NextHop $GW -interfaceAlias $IntAlias | Out-Null
                }
                #>
                $BgpAdapter="BGP_LocalPeer"
                if ( !(Get-NetAdapter $BgpAdapter -ea SilentlyContinue) )
                {
                    New-LoopbackAdapter -Name $BgpAdapter -Force | Out-Null
                }
                #Adding $BgpLocalIp is not plumbed
                if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $BgpLocalIp) ) 
                { 
                    Write-Host  "IP Address $BgpLocalIp is missing so adding it"
                    Get-NetAdapter $BgpAdapter | New-NetIPAddress -IPAddress $BgpLocalIp -PrefixLength 32 | Out-Null
                }
                
                try {
                    $bgpRouter = Get-BgpRouter -ErrorAction Ignore
                }
                catch { }
                
                if ( ! $bgpRouter ) {
                    Write-Host "Add BGP router Id=$BgpRouterId AS=$BgpLocalAs on $env:COMPUTERNAME"
                    Add-BgpRouter -BgpIdentifier $BgpLocalIp -LocalASN $BgpLocalAs                      
                }

                try {
                    $BpgPeer = Get-BgpPeer -Name $BgpPeerId -ErrorAction Ignore
                }
                catch { }

                if ( ! $BpgPeer ) {
                    Write-Host "Add BGP peer Id=$BgpPeerId RemoteAs=$BgpPeerAs PeerIp=$BgpPeerIp on $env:COMPUTERNAME"
                    Add-BgpPeer -Name $BgpPeerId -LocalIPAddress $BgpLocalIp -LocalASN $BgpLocalAs -PeerIPAddress $BgpPeerIp -PeerASN $BgpPeerAs `
                        -OperationMode Mixed -PeeringMode Automatic
                }   
            }

            #Adding Local Loopback to simulate remote site
            $TenantRemoteSubnets = $vgw.Properties.NetworkConnections.Properties.Routes.DestinationPrefix
            foreach ( $TenantRemoteSubnet in $TenantRemoteSubnets )
            {
                $Net    = $TenantRemoteSubnet.split("/")[0]
                [int]$Cidr   = $TenantRemoteSubnet.split("/")[1]
                $LocalLoopback=$ConnectionType+"_Dummy_Remote_"+$Net

                if ( $cidr -lt 32)
                {
                    $Last = [int]$Net.split(".")[-1]
                    $Last++
                    $Ip = $Net -Replace "(\d+).(\d+).(\d+).(\d+)",('$1'+"."+'$2'+"."+'$3'+"."+$Last)
                    if ( !(Get-NetAdapter $LocalLoopback -ea SilentlyContinue) )
                    {
                        New-LoopbackAdapter -Name $LocalLoopback -Force | Out-Null
                    }
                     #Adding $Ip is not plumbed
                    if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $Ip) ) 
                    { 
                        Write-Host  "IP Address $Ip is missing so adding it"
                        Get-NetAdapter $LocalLoopback | New-NetIPAddress -IPAddress $Ip -PrefixLength 32 | Out-Null
                    }
                }
            }
        } -ArgumentList $vgw,$vnet,$vTenantvGWs
    } -ArgumentList $LocalAdminCredential, $PhysicalGwVMName, ($vgw  | ConvertTo-Json -Depth 100), ($vnet  | ConvertTo-Json -Depth 100), $configdata.TenantvGWs
}

#Configuring iDNS
$DomainJoinUserNameDomain = $configdata.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $configdata.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $configdata.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $configdata.LocalAdminDomainUser.Split("\")[1]

New-SDNiDNSConfiguration ($uri -replace "https://","") $LocalAdminDomainUserDomain $LocalAdminDomainUserName `
    $DomainJoinPassword $($env:LOGONSERVER -replace "\\","") "sdn-cloud.net" $DomainJoinCredential 

$regfile=(pwd).path+"\utils\iDNS.reg"

(gc $regfile) | %{ $_ -replace '"Forwarders"="(\d+).(\d+).(\d+).(\d+)"',(('"Forwarders"=')+'"'+$($configdata.ManagementDNS)+'"') } > $regfile
invoke-command $configdata.HYPV -credential $DomainJoinCredential {
    $regfile=$args[0]
    Write-Host "Pushing DNSProxy config to registry on $env:computername"
    cmd.exe /c "reg import $regfile 2>&1"
    restart-service NcHostAgent -Force
    restart-service SlbHostAgent
} -Argumentlist $regfile 

foreach ($TenantVM in $configdata.TenantVMs) 
{
    Write-SDNNestedLog "Restarting $TenantVM"
    Get-VM -ComputerName $configdata.HYPV $TenantVM | Restart-VM -force
}