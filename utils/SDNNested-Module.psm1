function Write-SDNNestedLog 
{
    Param([String] $Message)

    $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
    $FormattedMessage = "[$FormattedDate] $Message"
    write-Host -ForegroundColor yellow $FormattedMessage

    $formattedMessage | out-file ".\SDNNestedLog.txt" -Append
}


function Get-IPLastAddressInSubnet {
    param([string] $subnet)
    write-SDNNestedLog "$($MyInvocation.InvocationName)"
    write-SDNNestedLog "   -Subnet: $subnet"

    $prefix = ($subnet.split("/"))[0]
    $bits = ($subnet.split("/"))[1]

    $ip = [IPAddress] $prefix
    if ($ip.AddressFamily -eq "InterNetworkV6") {
        $totalbits = 128
    }
    else {
        $totalbits = 32
    }

    $bytes = $ip.getaddressbytes()
    $rightbits = $totalbits - $bits
    
    write-SDNNestedLog "rightbits: $rightbits"
    $i = $bytes.count - 1
    while ($rightbits -gt 0) {
        if ($rightbits -gt 7) {
            write-SDNNestedLog "full byte"
            $bytes[$i] = $bytes[$i] -bor 0xFF
            $rightbits -= 8
        }
        else {
            write-SDNNestedLog "Final byte: $($bytes[$i])"
            $bytes[$i] = $bytes[$i] -bor (0xff -shr (8 - $rightbits))
            write-SDNNestedLog "Byte: $($bytes[$i])"
            $rightbits = 0
        }
        $i--
    }

    $ip2 = [IPAddress] $bytes 

    $return = $ip2.IPAddressToString
    write-SDNNestedLog "$($MyInvocation.InvocationName) Returns $return"
    $return
}

function GetCred {
    param(
        [String] $SecurePasswordText,
        [PSCredential] $Credential,
        [String] $Message,
        [String] $UserName
    )
    
    Write-SDNNestedLog "Using credentials from the command line."    
    return  get-Credential -Message $Message -UserName $UserName
}


function WaitLocalVMisBooted()
{
    param(
        [String] $VMName,
        [PSCredential] $Credential
    )

    Write-SDNNestedLog "Waiting till $VMName is READY"

    Write-Host "Waiting till $VMName is READY" -NoNewline
    
    $loop = $true
    while ( $loop )
    {
        $ps = $null
        $result = ""

        klist purge | out-null  #clear kerberos ticket cache 
        Clear-DnsClientCache    #clear DNS cache in case IP address is stale

        $ps = new-pssession -VMName $VMName -Credential $Credential -ErrorAction SilentlyContinue
        if( $ps )
        {
            Start-Sleep 1
            $result = Invoke-Command -Session $ps -ScriptBlock  {
                if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") 
                {
                    "RebootPending"
                } 
                else
                {
                    $env:COMPUTERNAME 
                }
            }
            remove-pssession $ps
        }

        if ( $result -eq $VMName )
        { 
            $loop = $false 
            break
        }
        if ( $result -eq "RebootPending" )
        { 
            Start-Sleep 30
        }

        Start-Sleep 5   
        Write-Host "." -NoNewline
    }
    Write-Host "[OK]"

    Write-SDNNestedLog "$VMName is READY"
    Start-Sleep 10
}
function Add-UnattendFileToVHD 
{
    
    Param(
        [String] $VHD, 
        [String] $ProductKey = "",
        [String] $DomainJoin,
        [String] $ComputerName,
        [String] $KeyboardLayout,
        [String] $DomainFDQN,
        [String] $CredentialDomain,
        [String] $CredentialPassword,
        [String] $CredentialUsername,
        [String] $LocalAdminPassword,
        [Object] $NICs
    )

    Write-SDNNestedLog "Generating and injecting unattend.xml to $VHD"

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $MountPath = $TempFile.FullName

    New-Item -ItemType Directory -Force -Path $MountPath | out-null

    Write-SDNNestedLog "Mounting $VHD file"
    Mount-WindowsImage -ImagePath $VHD -Index 1 -path $MountPath | out-null

    $TimeZone = (Get-TimeZone).id
    $count = 1
    $TCPIPInterfaces = ""
    $dnsinterfaces = ""

    foreach ($Nic in $NICs) {
        
        #$MacAddress = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"

        if (![String]::IsNullOrEmpty($Nic.IPAddress)) {
            $sp = $NIC.IPAddress.Split("/")
            $IPAddress = $sp[0]
            $SubnetMask = $sp[1]
    
            $Gateway = $Nic.Gateway
            $NicName = $Nic.Name

            $gatewaysnippet = ""
    
            if (![String]::IsNullOrEmpty($Gateway)) {
                $gatewaysnippet = @"
                <routes>
                    <Route wcm:action="add">
                        <Identifier>0</Identifier>
                        <Prefix>0.0.0.0/0</Prefix>
                        <Metric>20</Metric>
                        <NextHopAddress>$Gateway</NextHopAddress>
                    </Route>
                </routes>
"@
            }
    
            $TCPIPInterfaces += @"
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <Identifier>$NicName</Identifier>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$SubnetMask</IpAddress>
                    </UnicastIpAddresses>
                    $gatewaysnippet
                </Interface>
"@ 
        }
        else {
            $TCPIPInterfaces += @"
            <Interface wcm:action="add">
                <Ipv4Settings>
                    <DhcpEnabled>true</DhcpEnabled>
                </Ipv4Settings>
                <Identifier>$NicName</Identifier>
            </Interface>
"@ 

        }        
        $alldns = ""
        foreach ($dns in $Nic.DNS) {
            $alldns += '<IpAddress wcm:action="add" wcm:keyValue="{1}">{0}</IpAddress>' -f $dns, $count++
        }

        if ( $null -eq $Nic.DNS -or $Nic.DNS.count -eq 0) {
            $dnsregistration = "false"
        }
        else {
            $dnsregistration = "true"
        }

        $dnsinterfaces += @"
            <Interface wcm:action="add">
                <DNSServerSearchOrder>
                $alldns
                </DNSServerSearchOrder>
                <Identifier>$NicName</Identifier>
                <EnableAdapterDomainNameRegistration>$dnsregistration</EnableAdapterDomainNameRegistration>
            </Interface>
"@
    }

    
    $UnattendedJoin = @"
    
                    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Identification>
                    <Credentials>
                        <Domain>$CredentialDomain</Domain>
                        <Password>$CredentialPassword</Password>
                        <Username>$CredentialUsername</Username>
                    </Credentials>
                    <JoinDomain>$DomainFQDN</JoinDomain>
                </Identification>
            </component>    
"@

    $UnattendedDomainAccount = @"
                        <DomainAccounts>
                            <DomainAccountList wcm:action="add">
                                <DomainAccount wcm:action="add">
                                    <Name>$DomainAdminUserName</Name>
                                    <Group>Administrators</Group>
                                </DomainAccount>
                                <Domain>$DomainAdminDomain</Domain>
                            </DomainAccountList>
                        </DomainAccounts>
"@

    if ( $ComputerName -match "DC" -or $ComputerName -match "GW" -or $ComputerName -match "Contoso" -or $ComputerName -match "Fabrikam" ) {
        $UnattendedJoin = $null
    }

    if ( $ComputerName -match "GW" -or $ComputerName -match "Contoso" -or $ComputerName -match "Fabrikam" ){
        $UnattendedDomainAccount = $null
    }

    $UnattendFile = @"
<?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend">
        <settings pass="specialize">
            <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <DomainProfile_EnableFirewall>false</DomainProfile_EnableFirewall>
                    <PrivateProfile_EnableFirewall>false</PrivateProfile_EnableFirewall>
                    <PublicProfile_EnableFirewall>false</PublicProfile_EnableFirewall>
                </component>
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ComputerName>$ComputerName</ComputerName>
                <ProductKey>$ProductKey</ProductKey>
            </component>
            <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <fDenyTSConnections>false</fDenyTSConnections>
            </component>
            <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <UserLocale>en-us</UserLocale>
                <UILanguage>en-us</UILanguage>
                <SystemLocale>en-us</SystemLocale>
                <InputLocale>$KeyboardLayout</InputLocale>
            </component>
            <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <IEHardenAdmin>false</IEHardenAdmin>
                <IEHardenUser>false</IEHardenUser>
            </component>
            <component name="Microsoft-Windows-TCPIP" processorArchitecture="wow64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Interfaces>
                    $TCPIPInterfaces
                </Interfaces>
            </component>
            <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Interfaces>
                     $DNSInterfaces
                </Interfaces>
            </component>$UnattendedJoin
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                   <UserAccounts>
                    <AdministratorPassword>
                        <Value>$LocalAdminPassword</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>$UnattendedDomainAccount
                </UserAccounts>
                <TimeZone>$TimeZone</TimeZone>
                <OOBE>
                    <HideEULAPage>true</HideEULAPage>
                    <SkipUserOOBE>true</SkipUserOOBE>
                    <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                    <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                    <NetworkLocation>Work</NetworkLocation>
                    <ProtectYourPC>1</ProtectYourPC>
                    <HideLocalAccountScreen>true</HideLocalAccountScreen>
                </OOBE>
            </component>
        </settings>
    <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@
 
   Write-SDNNestedLog "Writing unattend.xml to $MountPath\unattend.xml"
    Set-Content -value $UnattendFile -path "$MountPath\unattend.xml" | out-null
    
    DisMount-WindowsImage -Save -path $MountPath | out-null
    Remove-Item $MountPath -Recurse -Force
}



Function Enable-AzRmVMAutoShutdown
{
    [CmdletBinding()]
    Param 
    (
        [Parameter(Mandatory = $true)] 
        [string] $ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string] $VirtualMachineName,
        [int] $ShutdownTime = 1900,
        [string] $TimeZone = 'Romance Standard Time'
    )
    
    Try    
    {
        $Location = (Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName).Location
        $SubscriptionId = (Get-AzContext).Subscription.SubscriptionId
        $VMResourceId = (Get-AzVm -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName).Id
        $ScheduledShutdownResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/microsoft.devtestlab/schedules/shutdown-computevm-$VirtualMachineName"

        $Properties = @{}
        $Properties.Add('status', 'Enabled')
        $Properties.Add('taskType', 'ComputeVmShutdownTask')
        $Properties.Add('dailyRecurrence', @{'time'= $ShutdownTime})
        $Properties.Add('timeZoneId', $TimeZone)
        $Properties.Add('notificationSettings', @{status='Disabled'; timeInMinutes=15})
        $Properties.Add('targetResourceId', $VMResourceId)

        New-AzResource -Location $Location -ResourceId $ScheduledShutdownResourceId -Properties $Properties -Force
    }
    Catch {Write-Error $_}
}

######
function New-SdnNestedVm() 
{
    param(
        [String] $VMLocation,
        [String] $VMName,
        [String] $VHDSrcPath,
        [String] $VHDName,
        [Int64] $VMMemory,
        [int] $VMProcessorCount,
        [String] $SwitchName = "",
        [Object] $Nics,
        [String] $CredentialDomain,
        [String] $CredentialUserName,
        [String] $CredentialPassword,
        [String] $JoinDomain,
        [String] $LocalAdminPassword,
        [String] $DomainAdminDomain,
        [String] $DomainAdminUserName,
        [String] $ProductKey = "",
        [String] $Locale = [System.Globalization.CultureInfo]::CurrentCulture.Name,
        [String] $TimeZone = [TimeZoneInfo]::Local.Id,
        [String] $DomainFQDN
    )
    
    $CurrentVMLocationPath = "$VMLocation\$VMName"
    $VHDTemplateFile = "$VHDSrcPath\$VHDName"

    Write-SDNNestedLog "Creating VM $VMName on $env:computername" 

    if ( !(Test-Path $CurrentVMLocationPath) ) {  
       Write-SDNNestedLog "Creating folder $CurrentVMLocationPath"
        New-Item -ItemType Directory $CurrentVMLocationPath | Out-null
    }

    Write-SDNNestedLog "Copying VHD template $VHDTemplateFile to $CurrentVMLocationPath"
    
    #Optimization to copy locally the syspreped VHDX once and then use it
    <#
    if ( ! ( Test-Path "$VMLocation\$VHDName" ) )
    {
        Copy-Item -Path $VHDTemplateFile -Destination $VMLocation -Recurse -Force | Out-Null
    }
    Copy-Item -Path "$VMLocation\$VHDName" -Destination $CurrentVMLocationPath -Recurse -Force | Out-Null
    #>

    Copy-Item -Path $VHDTemplateFile -Destination $CurrentVMLocationPath -Recurse -Force | Out-Null
    
    $params = @{
        'VHD'                = "$CurrentVMLocationPath\$VHDName";
        'ProductKey'         = $ProductKey;
        'IpGwAddr'           = $IpGwAddr;
        'DomainJoin'         = $JoinDomain;
        'ComputerName'       = $VMName;
        'KeyboardLayout'     = $KeyboardLayout;
        'DomainFDQN'         = $DomainFQDN;
        'CredentialDomain'   = $CredentialDomain;
        'CredentialPassword' = $CredentialPassword;
        'CredentialUsername' = $CredentialUserName;
        'LocalAdminPassword' = $LocalAdminPassword;
        'NICS'               = $Nics;
    }

    #Preparing Unatting process => building unattend.xml file
    Add-UnattendFileToVHD @params
    
    if ( Test-Path $CurrentVMLocationPath) {
        $VHDOsFile = $(Get-Item $CurrentVMLocationPath\*.vhdx).FullName

        $NewVM = New-VM -Generation 2 -Name $VMName -Path $CurrentVMLocationPath -MemoryStartupBytes $VMMemory -VHDPath $VHDOsFile -SwitchName $SwitchName
        $NewVM | Set-VM -processorcount $VMProcessorCount | out-null

        for ( $i = 0; $i -lt $Nics.count; $i++ ) {
            if ( $i -gt 0) 
            {
                $NewVM | Add-VMNetworkAdapter -SwitchName $SwitchName
                $vmNIC = ($NewVM | Get-VMNetworkAdapter)[-1]
                $vmNIC | Set-VMNetworkAdapterVlan -Access -VlanId $Nics[0].VLANID            
            }
            else 
            { 
                #Hard to predict how PNP manager is enumerating NIC so set MGTM vLAN ID to all vNICS
                $NewVM | Get-VMNetworkAdapter | Set-VMNetworkAdapterVlan -Access -VlanId $Nics[0].VLANID            
            }
        }
    } 
}

function New-ToRRouter()
{
    param(
        [String] $VMName,
        [PSCredential] $credential,
        [array] $TORrouter
    )
    Write-SDNNestedLog "--> Tor Router : Staging $VMName"

    #Adding RRAS and BGP config
    Add-WindowsFeatureOnVM $VMName $credential RemoteAccess

    Invoke-Command -VMName $VMName -Credential $credential { 
        $TORrouter = $args[0]
        
        Install-RemoteAccess -VpnType RoutingOnly

        Write-Host  "Configuring $env:COMPUTERNAME as TOR router" 
        Write-Host  "Configuring BGP router and BGP peers on $env:COMPUTERNAME"   

        Add-BgpRouter -BgpIdentifier $TORrouter.BgpRouter.RouterIPAddress -LocalASN $TORrouter.BgpRouter.RouterASN
        
        foreach ( $BgpPeer in $TORrouter.BgpPeers ) 
        {
            Add-BgpPeer -Name $BgpPeer.Name -LocalIPAddress $TORrouter.BgpRouter.RouterIPAddress -PeerIPAddress $BgpPeer.PeerIPAddress `
                -PeerASN $TORrouter.SDNASN -OperationMode Mixed -PeeringMode Automatic 
        }

        foreach ( $route in $TORrouter.StaticRoutes ) {
            Write-Host  "Adding Static routes $($route.Route) via $($route.NextHop)"
            $NextHopSplit = $($route.NextHop).split(".")
     
            $ifIndex = (Get-NetIPAddress | ? IPAddress -Match "$($NextHopSplit[0]).$($NextHopSplit[1]).$($NextHopSplit[2])").InterfaceIndex

            if ( $ifIndex ){
                Write-Host  "Adding Static route Dst=$($route.Route) NextHop=$($route.NextHop) ifIndex=$ifIndex"
                New-NetRoute -DestinationPrefix $route.Route -NextHop $route.NextHop -ifIndex $ifIndex | Out-Null
            }
            else { 
               Write-Host  "ERROR: Failded to add Static route Dst=$($route.Route) NextHop=$($route.NextHop) ifIndex=$ifIndex"
            }
        }

        if ( $TORrouter.InternetNAT )
        {
            $In=(Get-NetAdapter | Get-NetIpAddress | ? IpAddress -match $TORrouter.InsideNAT).InterfaceAlias
            $Out=(Get-NetAdapter | Get-NetIpAddress | ? IpAddress -match $TORrouter.OutsideNAT).InterfaceAlias
            Write-Host  "Configuring NAT for Internet access on ToR Router"
            netsh routing ip nat install
            netsh routing ip nat  add int $in Private
            netsh routing ip nat  add int $out Full
        }

        add-content C:\ToR.txt ""        
    } -ArgumentList $TORrouter
    Write-SDNNestedLog "<-- Tor Router : Staging $VMName is done"
}

function Add-vNicIpConfig(){
    param(
        [hashtable] $vNIC
    )

    $NetAdapter = Get-NetAdapter | ? Name -Match $vNIC.Name

    $IpAddr         = $vNIC.IpAddress.split("/")[0]
    $PrefixLength   = $vNIC.IpAddress.split("/")[1]
    $DNS            = $vNIC.DNS

    if( $NetAdapter )
    {
        $result =  $NetAdapter | Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ? IPAddress -eq $IpAddr 
        if ( ! ( $result  ) )
        {
            Write-Host "Configure Ip address/mask=$IpAddr/$PrefixLength Adapter=$($NetAdapter.Name) Host=$env:COMPUTERNAME"
            $NetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IpAddr -PrefixLength $PrefixLength | Out-Null
            Write-Host "Configure DNS $DNS NetAdapter:$($NetAdapter.Name) Host=$env:COMPUTERNAME"
            $NetAdapter | Set-DnsClientServerAddress -ServerAddresses $DNS
        }
        else
        {
           Write-SDNNestedLog "$IpAddr already plumbed on Adapter=$($NetAdapter.Name) Host=$env:COMPUTERNAME"
        }
    }
    else {Write-SDNNestedLog  "ERROR: Failed to configure IpConfig and DNS vNIC=$($vNIC.Name) Host=$env:COMPUTERNAME" }
}
function Connect-HostToSDN()
{
    param(
        [array] $vNICs
    )

    foreach($vNIC in $vNICs)
    {

        if ( !(  Get-VMNetworkAdapter -ManagementOS -Name $vNIC.Name -SwitchName $vNIC.SwitchName -ErrorAction SilentlyContinue ) )
        {
            Write-SDNNestedLog  "Adding vNIC=$($vNIC.Name) on Switch=$($vNIC.SwitchName) Host=$env:COMPUTERNAME"
            Add-VMNetworkAdapter -ManagementOS -Name $vNIC.Name -SwitchName $vNIC.SwitchName 
        }
        while ( !( Get-VMNetworkAdapter -ManagementOS -Name $vNIC.Name -SwitchName  $vNIC.SwitchName -ErrorAction Ignore)){ sleep 1}
        
        Write-SDNNestedLog "Enabling Ethernet Jumbo Frames"
        Get-NetAdapter -Name "*$($vNIC.Name)*" | Get-NetAdapterAdvancedProperty | ? RegistryKeyword -EQ "*JumboPacket" | `
            Set-NetAdapterAdvancedProperty -RegistryValue 9014
        #Configure IpConfig
        Add-vNicIpConfig $vNIC
        #VLAN
        Write-SDNNestedLog "VLAN: Configuring $($vNIC.Name) in ACCESS mode VLAN=$($vNIC.VLANID)"
        Get-VMNetworkAdapter -ManagementOS -Name $vNIC.Name | Set-VMNetworkAdapterVlan -Access -VlanId $vNIC.VLANID
        
        if ( $vNIC.Name -eq "Internet")
        {
            Write-SDNNestedLog "NAT: Configuring NetNAT on $($vNIC.NAME)"
            
            Get-NetNat | Remove-NetNat -Confirm:$false
            $NetAddr         = $vNIC.IpAddress.split("/")[0] -replace ".[0-9]+$",".0"
            $PrefixLength   = $vNIC.IpAddress.split("/")[1]
            
            New-NetNat -Name $($vNIC.NAME) -InternalIPInterfaceAddressPrefix "$NetAddr/$PrefixLength" -Confirm:$false | Out-Null
        }
    
        #Adding IPRoute if needed
        if ( $vNIC.NetRoute )
        {
            $NetRoute = $vNIC.NetRoute
            if ( ! (Get-NetRoute -DestinationPrefix  $NetRoute.Destination -ErrorAction SilentlyContinue ) )
            {
                $NextHopSplit = $($NetRoute.NextHop).split(".")
                $ifIndex = (Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -Match "$($NextHopSplit[0]).$($NextHopSplit[1]).$($NextHopSplit[2])").InterfaceIndex

                if ( $ifIndex )
                {
                    New-NetRoute -AddressFamily "IPv4" -DestinationPrefix $NetRoute.Destination -NextHop $NetRoute.NextHop -InterfaceIndex $IfIndex | Out-Null
                    Write-SDNNestedLog  "NetRoute SDN VIP pool=$($NetRoute.Destination) is added on $env:computername"
                }
                else  {Write-SDNNestedLog  "ERROR: NetRoute=$($NetRoute.Destination) on $env:computername to reach SDN VIP has not been added" }
            }
            else{ Write-SDNNestedLog "NetRoute SDN VIP pool=$($NetRoute.Destination) already present on $env:computername" }
        }
    }
}

function Add-WindowsFeatureOnVM() 
{
    param(
        [String] $VMName,
        [PSCredential] $credential,
        [String[]] $FeatureList
    )

    foreach( $Feature in $FeatureList)
    {
        Write-Host "Installing Windows Feature $feature on $VMName"
        Invoke-Command -VMName $VMName -Credential $credential -ErrorAction SilentlyContinue {
            $Feature=$args[0]
            if ( $Feature -eq "RemoteAccess")
            { 
                $res = Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTool
            }
            else 
            { 
                $res = Install-WindowsFeature -Name $Feature -IncludeManagementTools
            }       

            if ( $res.RestartNeeded -eq "Yes" ){ Write-Host "Restarting $env:COMPUTERNAME"; restart-computer -Force }
        } -ArgumentList $Feature     
        WaitLocalVMisBooted $VMName $credential
    }
}

<#
    Promote VM to be a DC using config passed in. If it is the 1st DC, installing Forest 
#>
function New-SDNNestedADDSForest()
{
    param(
        [String] $VMName,
        [pscredential] $Credential,
        [String] $DomainFQDN
    )
    
    $password = $Credential.GetNetworkCredential().Password
    $SafeModePwd = $password | ConvertTo-SecureString -asPlainText -Force
    
    $paramsDeployForest = @{
        DomainName                    = $DomainFQDN
        DomainMode                    = 'WinThreshold'
        DomainNetBiosName             = $DomainFQDN.split(".")[0]
        SafeModeAdministratorPassword = $SafeModePwd

    }

    Write-SDNNestedLog  "--> Installing AD-DS on vm $VMName"
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools | Out-Null
        
        $params = @{
            DomainName                    = $args.DomainName
            DomainMode                    = $args.DomainMode
            SafeModeAdministratorPassword = $args.SafeModeAdministratorPassword
        }
        Install-ADDSForest @params -InstallDns -Confirm -Force | Out-Null
        #
    } -ArgumentList $paramsDeployForest
    Write-SDNNestedLog  "<-- Installing AD-DS on vm $VMName"
}

function Add-SDNNestedADDSDomainController()
{
    param(
        [String] $VMName,
        [pscredential] $Credential,
        [String] $DomainFQDN
    )

    $paramsAddDc = @{
        DomainName                    = $DomainFQDN
        Credential                    = $Credential
    }

    Write-SDNNestedLog  " --> Promote vm $env:COMPUTERNAME as DC to domain $($params.DomainName)"
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        $params = @{
            DomainName                    = $args.DomainName
            Credential                    = $args.Credential
        }

        Install-ADDSDomainController @params -InstallDns -Confirm -Force | Out-Null
    } -ArgumentList $paramsAddDc
    Write-SDNNestedLog  "<-- Promote vm $env:COMPUTERNAME as DC to domain $($params.DomainName)"
}

function Set-DnsConfigBindings()
{
    param(
        [String] $server,
        [String] $ListeningIP,
        [pscredential] $credential
    )

    Write-SDNNestedLog "Removing 2nd NIC from DNS zone and DNS server bindings on $server" 

    Invoke-Command -VMName $server -Credential $credential { 
        $ListeningIP = $args[0] 

        $AdaptersToDisable=Get-NetAdapter Ethernet | Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -NotMatch $ListeningIP
        #Removing DNS registration on 2nd adapter
        
        Write-Host  "Configuring DNS server to only listening on mgmt NIC"   
        $AdaptersToDisable | Set-DnsClient -RegisterThisConnectionsAddress $false
        dnscmd /ResetListenAddresses $ListeningIP | Out-Null
        
        Restart-Service DNS
        sleep 5
        ipconfig /registerdns | Out-Null
    } -ArgumentList $ListeningIP
}

function Add-DnsForwarders
{
    param (
        [String] $server,
        [Boolean] $InheritFromHypvHost,
        [pscredential] $credential
    )
    
    Write-SDNNestedLog  "Adding DNS Forwarder on $server"
    $DNS=@()
    $DNS+="8.8.8.8"
    if ( $InheritFromHypvHost )
    {
        $DNS+=(Get-DnsClientServerAddress -AddressFamily IPv4 | ? InterfaceAlias -Match ^Ethernet).ServerAddresses
    }
    invoke-command -VMName $server -Credential $credential {
        $DNS=$args
        foreach($addr in $DNS)
        {
            Add-DnsServerForwarder -IPAddress $addr 
        }
        Set-DnsServerForwarder -UseRootHint $false -Timeout 5
    } -ArgumentList $DNS
      
}
function Add-VMDataDisk() {
    param(
        [String] $VMName,
        [String] $DiskNameStr,
        [int64] $DiskSize,
        [int] $DiskNumber
    )

    $VM = (Get-VM $VMName)
    $LocalVMPath = $VM.Path

    for ($i = 0; $i -lt $DiskNumber; $i++) 
    {
        $VHDFullPath = "$LocalVMPath\$VMNAme-$DiskNameStr-$i.vhdx"
        Write-SDNNestedLog  "Creating VHDX FILE $VHDFullPath" 
        New-VHD -Path $VHDFullPath -SizeBytes $DiskSize -Dynamic | Out-Null
        Write-SDNNestedLog  "Attaching VM DataDisks $VHDFullPath to $VMName"
        Add-VMHardDiskDrive -Path $VHDFullPath -VMName $VMName -ControllerType SCSI | Out-Null
    }   
}

function New-SDNS2DCluster {
    param (
        [String[]] $Nodes,
        [PSCredential] $credential,
        [String] $IpAddress,
        [String] $ClusterName,
        [boolean] $dummy = $false
    )

    if ( ! $dummy )
    {
        Write-SDNNestedLog "--> S2DCONFIG: Cleaning Drives"
        Invoke-Command -VMName ($Nodes) -Credential $credential {
            Update-StorageProviderCache
            Get-StoragePool | Where-Object IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
            Get-StoragePool | Where-Object IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
            Get-StoragePool | Where-Object IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
            Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
            Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | ForEach-Object {
                $_ | Set-Disk -isoffline:$false
                $_ | Set-Disk -isreadonly:$false
                $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
                $_ | Set-Disk -isreadonly:$true
                $_ | Set-Disk -isoffline:$true
            }
            Get-Disk | Where-Object Number -Ne $Null | Where-Object IsBoot -Ne $True | Where-Object IsSystem -Ne $True | Where-Object PartitionStyle -Eq RAW | Group-Object -NoElement -Property FriendlyName
        } | Sort-Object -Property PsComputerName, Count
        Write-SDNNestedLog "<-- S2DCONFIG: Cleaning Drives done"
    }
        
    Write-SDNNestedLog "--> S2DCONFIG: Forming cluster $ClusterName / $IpAddress "
    Invoke-Command -VMName $Nodes[0] -Credential $credential -ScriptBlock {
         
        $ClusterNodes = $args[0]
        $ClusterIP = $args[1]
        $ClusterName = $args[2]
        $dummy  = $args[3]

        # Create S2D Cluster
        Import-Module FailoverClusters 

        #Test-Cluster –Node $ClusterNodes[0], $ClusterNodes[1] –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"

        # Create Cluster
        Write-Host "Forming cluster $ClusterName / $ClusterIP "
        New-Cluster -Name $ClusterName -Node $ClusterNodes -StaticAddress $ClusterIP -NoStorage | Out-Null

        # Invoke Command to enable S2D on SDNCluster   
        Write-Host "Enabling S2D on cluster $ClusterName / $ClusterIP "     
        Enable-ClusterS2D -CacheState Disabled -AutoConfig:0 -SkipEligibilityChecks -Confirm:$false | Out-Null
        if ( ! $dummy )
        {
            $params = @{
                    StorageSubSystemFriendlyName = "*Clustered*"
                    FriendlyName                 = 'SDN_S2D_Storage'
                    ProvisioningTypeDefault      = 'Fixed'
                }

            Write-Host "Creating S2D Storage pool on cluster $ClusterName / $ClusterIP "     
            New-StoragePool @params -PhysicalDisks (Get-PhysicalDisk | ? CanPool | ? PartitionStyle -ne GPT) | Out-Null

            Get-PhysicalDisk | Where-Object  MediaType -eq "UnSpecified" | Set-PhysicalDisk -MediaType HDD | Out-Null

            $params = @{  
                FriendlyName            = 'S2D_CSV1' 
                FileSystem              = 'CSVFS_ReFS'
                StoragePoolFriendlyName = 'SDN_S2D_Storage'
                PhysicalDiskRedundancy  = 1    
            }

            Write-Host "Creating new S2D cluster volume on cluster $ClusterName / $ClusterIP "     
            New-Volume @params -UseMaximumSize | Out-Null

            # Set Virtual Environment Optimizations
            Get-storagesubsystem clus* | set-storagehealthsetting -name “System.Storage.PhysicalDisk.AutoReplace.Enabled” -value “False”
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530
        }
    } -ArgumentList $Nodes, $IpAddress, $ClusterName, $dummy
    Write-SDNNestedLog "<-- S2DCONFIG: Forming cluster $ClusterName / $IpAddress is done"
}


#######
#######
####### NORTHBOUND API - functions (Add Tenant , Add SLB , Remove, Get , and so on)
#######
#######
function Get-HNVProviderLogicalNetwork()
{
    param (
        [String] $uri
    )
    
    $logicalnetworks = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri 
        
    foreach ($ln in $logicalnetworks) {  
        if ($ln.Properties.NetworkVirtualizationEnabled -eq "True") {  
            $HNVProviderLogicalNetwork = $ln  
        }
    }   
    return $HNVProviderLogicalNetwork
}

function Get-SDNGatewayPool()
{
    param (
        [String] $uri,
        [String] $GwPoolName = "Default"
    )

    $gwPool = Get-NetworkControllerGatewayPool -ConnectionUri $uri  | ? ResourceId -match $GwPoolName

    return $gwPool
}

function New-TenantVirtualNetwork()
{
    param (
        [String] $uri,
        [hashtable] $Tenant,
        [psobject] $HNVProviderLogicalNetwork
    )

    Write-SDNNestedLog  "Pushing VNET config for $($Tenant.Name) to $uri"
    
    #Create the Virtual Network
    $vnetproperties = new-object Microsoft.Windows.NetworkController.VirtualNetworkProperties  
    $vnetproperties.AddressSpace = new-object Microsoft.Windows.NetworkController.AddressSpace  
    $vnetproperties.AddressSpace.AddressPrefixes = $Tenant.TenantVirtualNetworkAddressPrefix    
    $vnetproperties.LogicalNetwork = $HNVProviderLogicalNetwork  
        
    foreach( $subnet in $Tenant.TenantVirtualSubnets )
    {
        $vsubnet = new-object Microsoft.Windows.NetworkController.VirtualSubnet  
        $vsubnet.ResourceId = $subnet.Name  
        $vsubnet.Properties = new-object Microsoft.Windows.NetworkController.VirtualSubnetProperties  
        #$vsubnet.Properties.AccessControlList = $acllist  
        $vsubnet.Properties.AddressPrefix = $subnet.AddressPrefix   
        $vnetproperties.Subnets += $vsubnet  
    }
    $vnet = New-NetworkControllerVirtualNetwork -ResourceId $Tenant.TenantVirtualNetworkName -ConnectionUri $uri `
        -Properties $vnetproperties -Force -PassInnerException

    return $vnet
}
function New-SDNVirtualGateway()
{
    param (
        [String] $uri,
        [String] $VirtualGatewayResourceId,
        [hashtable] $Tenant,
        [psobject] $Vnet,
        [String] $SubnetNameRegex,
        [psobject] $gwPool,
        [psobject] $HNVProviderLogicalNetwork
    )

    Write-SDNNestedLog  "Pushing vGW config for $($Tenant.Name) to $uri"
    # Create a new object for Tenant Virtual Gateway  
    $VirtualGWProperties = New-Object Microsoft.Windows.NetworkController.VirtualGatewayProperties   

    # Update Gateway Pool reference  
    $VirtualGWProperties.GatewayPools = @()   
    $VirtualGWProperties.GatewayPools += $gwPool   

    # Specify the Virtual Subnet that is to be used for routing between the gateway and Virtual Network   
    $VirtualGWProperties.GatewaySubnets = @()   
    for( $i=0;$i -lt $Vnet.Properties.Subnets.count; $i++ )
    {
        if (  $Vnet.Properties.Subnets[$i] | ? ResourceId -Match $SubnetNameRegex )
        {
            $VirtualGWProperties.GatewaySubnets  +=  $Vnet.Properties.Subnets[$i]
            #$Vnet.Properties.Subnets[$i]
        }
    }
    
    # Update the rest of the Virtual Gateway object properties  
    $VirtualGWProperties.RoutingType = "Dynamic"   
    $VirtualGWProperties.NetworkConnections = @()   
    $VirtualGWProperties.BgpRouters = @()   
    #$Vnet.Properties.Subnets 

    # Add the new Virtual Gateway for tenant   
    $virtualGW = New-NetworkControllerVirtualGateway -ConnectionUri $uri -ResourceId $VirtualGatewayResourceId `
        -Properties $VirtualGWProperties -PassInnerException -Force 

    return $virtualGW
}

function New-SDNVirtualGatewayNetworkConnections()
{
    param (
        [String] $uri,
        [hashtable] $gw,
        [string] $VirtualGatewayId
    )
    
    # Create a new object for the Tenant Network Connection  
    $nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties   

    if ( $gw.Type -eq "L3")
    {
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
             
        #$logicalsubnet  

        # Add the new Logical Network to Network Controller  
        $LogicalNetwork = Get-NetworkControllerLogicalNetwork -ConnectionUri $uri | ? ResourceId -eq $Gw.LogicalNetworkName
        if ( $null -eq $LogicalNetwork) 
        {
            $LogicalNetwork = New-NetworkControllerLogicalNetwork -ConnectionUri $uri `
                -ResourceId $Gw.LogicalNetworkName -Properties $lnProperties -Force
        }
             
        $logicalNetwork

        # Update the common object properties  
        $nwConnectionProperties.ConnectionType = $gw.Type

        $nwConnectionProperties.OutboundKiloBitsPerSecond = $gw.capacity
        $nwConnectionProperties.InboundKiloBitsPerSecond = $gw.capacity

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
    elseif ($gw.type -eq "GRE") 
    {
        # Update the common object properties  
        $nwConnectionProperties.ConnectionType = $gw.type
        $nwConnectionProperties.OutboundKiloBitsPerSecond =  $gw.capacity
        $nwConnectionProperties.InboundKiloBitsPerSecond =  $gw.capacity

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
    elseif ( $gw.type -eq "IPSEC") 
    {
        # Create a new object for Tenant Network Connection  
        $nwConnectionProperties = New-Object Microsoft.Windows.NetworkController.NetworkConnectionProperties   

        # Update the common object properties  
        $nwConnectionProperties.ConnectionType =  $gw.type   
        $nwConnectionProperties.OutboundKiloBitsPerSecond = $gw.capacity
        $nwConnectionProperties.InboundKiloBitsPerSecond = $gw.capacity 

        # Update specific properties depending on the Connection Type  
        $nwConnectionProperties.IpSecConfiguration = New-Object Microsoft.Windows.NetworkController.IpSecConfiguration   
        $nwConnectionProperties.IpSecConfiguration.AuthenticationMethod = $Gw.AuthenticationMethod   
        $nwConnectionProperties.IpSecConfiguration.SharedSecret = $Gw.PSK

        $nwConnectionProperties.IpSecConfiguration.QuickMode = New-Object Microsoft.Windows.NetworkController.QuickMode   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.PerfectForwardSecrecy = "PFS2048"   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.AuthenticationTransformationConstant = "SHA256128"   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.CipherTransformationConstant = "DES3"   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeSeconds = 1233   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.IdleDisconnectSeconds = 500   
        $nwConnectionProperties.IpSecConfiguration.QuickMode.SALifeTimeKiloBytes = 2000   

        $nwConnectionProperties.IpSecConfiguration.MainMode = New-Object Microsoft.Windows.NetworkController.MainMode   
        $nwConnectionProperties.IpSecConfiguration.MainMode.DiffieHellmanGroup = "Group2"   
        $nwConnectionProperties.IpSecConfiguration.MainMode.IntegrityAlgorithm = "SHA256"   
        $nwConnectionProperties.IpSecConfiguration.MainMode.EncryptionAlgorithm = "AES256"   
        $nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeSeconds = 1234   
        $nwConnectionProperties.IpSecConfiguration.MainMode.SALifeTimeKiloBytes = 2000   

        # L3 specific configuration (leave blank for IPSec)  
        $nwConnectionProperties.IPAddresses = @()   
        $nwConnectionProperties.PeerIPAddresses = @()

        # Tunnel Destination (Remote Endpoint) Address  
        $nwConnectionProperties.DestinationIPAddress = $Gw.IPSecPeer 

    }
     
    # Update the IPv4 Routes that are reachable over the site-to-site VPN Tunnel  
    $nwConnectionProperties.Routes = @()   
     
    foreach ( $RouteDstPrefix in $Gw.RouteDstPrefix) 
    {
        $ipv4Route = New-Object Microsoft.Windows.NetworkController.RouteInfo   
        $ipv4Route.DestinationPrefix = $RouteDstPrefix
        <# 
        if ( $gw.Type -eq "L3")
        { 
            $ipv4Route.NextHop = $Gw.PeerIpAddrGW[0] 
        }
        #>
        $ipv4Route.metric = 10   
        $nwConnectionProperties.Routes += $ipv4Route   
    }

     # Add the new Network Connection for the tenant
     New-NetworkControllerVirtualGatewayNetworkConnection -ConnectionUri $uri -VirtualGatewayId $VirtualGatewayId `
         -ResourceId "nwConnection_$($gw.Type)" -Properties $nwConnectionProperties -Force
}

function New-SDNVirtualGatewayBgpRouter()
{
    param (
        [String] $uri,
        [hashtable] $gw,
        [string] $VirtualGatewayId
    )

    # Create a new object for the Tenant BGP Router  
    $bgpRouterproperties = New-Object Microsoft.Windows.NetworkController.VGwBgpRouterProperties   

    # Update the BGP Router properties  
    $bgpRouterproperties.ExtAsNumber = $gw.BgpLocalExtAsNumber
    $bgpRouterproperties.RouterId = $gw.BgpLocalBRouterId
    $bgpRouterproperties.RouterIP = $gw.BgpLocalRouterIP  
        
    $bgpRouterResourceId="$($VirtualGatewayId)_$($gw.Type)_BGPRouter"
    # Add the new BGP Router for the tenant  
    $bgpRouter = New-NetworkControllerVirtualGatewayBgpRouter -ConnectionUri $uri -VirtualGatewayId $VirtualGatewayId `
        -ResourceId $bgpRouterResourceId -Properties $bgpRouterProperties -Force

    return $bgpRouter.ResourceId
}
function New-SDNVirtualGatewayBgpPeer()
{
    param (
        [String] $uri,
        [hashtable] $gw,
        [string] $BgpRouterId,
        [string] $VirtualGatewayId
    )

    #Configure BGP on the vGW 
    if ( $gw.BGPEnabled ) 
    {     
        Write-SDNNestedLog  "Pushing BGP config for $($gw.Tenant) vGW to $uri"

        # Create a new object for Tenant BGP Peer  
        $bgpPeerProperties = New-Object Microsoft.Windows.NetworkController.VGwBgpPeerProperties   

        # Update the BGP Peer properties  
        $bgpPeerProperties.PeerIpAddress = $gw.BgpPeerIpAddress   
        $bgpPeerProperties.AsNumber = $gw.BgpPeerAsNumber   
        $bgpPeerProperties.ExtAsNumber = $gw.BgpPeerExtAsNumber 

        $bgpRouter = Get-NetworkControllerVirtualGatewayBgpRouter -ConnectionUri $uri -VirtualGatewayId $VirtualGatewayId `
            -ResourceId $BgpRouterId

        $BgpPeerId = "BgpRouter_$($Gw.Tenant)_$($gw.Type)_BGPPeerAs$($Gw.BgpPeerAsNumber)" 
        # Add the new BGP Peer for tenant  
        New-NetworkControllerVirtualGatewayBgpPeer -ConnectionUri $uri -VirtualGatewayId $VirtualGatewayId -BgpRouterName $bgpRouter.ResourceId `
            -ResourceId $BgpPeerId -Properties $bgpPeerProperties -Force
    }
    else
    {
        Write-SDNNestedLog  "Cannot add BGPPeer on $VirtualGatewayId as BGP is not enabled on"
    }
}

function New-SDNNetworkInterface()
{
    param (
        [String] $uri,
        [string] $vmnicResourceId,
        [hashtable] $NIC,
        [string] $TenantSubnetRef
    )

    $vmnicproperties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceProperties
    $vmnicproperties.PrivateMacAllocationMethod = "Dynamic"                
    $vmnicproperties.IsPrimary = $true 

    $vmnicproperties.DnsSettings = new-object Microsoft.Windows.NetworkController.NetworkInterfaceDnsSettings
    
    if ( $NIC.DNS )
    {
        $vmnicproperties.DnsSettings.DnsServers = $NIC.DNS
    }

    $ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $ip = $NIC.IPAddress.split("/")[0]
    
    $ipconfiguration.resourceid = "IpConfig_$ip"
    $ipconfiguration.properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
    $ipconfiguration.properties.PrivateIPAddress = $ip
    $ipconfiguration.properties.PrivateIPAllocationMethod = "Static"

    $ipconfiguration.properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet

    $ipconfiguration.properties.subnet.ResourceRef =  $TenantSubnetRef
    $vmnicproperties.IpConfigurations = @($ipconfiguration)

    Write-SDNNestedLog  "Pushing $vmnicResourceId NIC config to REST API"

    $SDNNic = New-NetworkControllerNetworkInterface -ResourceId $vmnicResourceId -Properties $vmnicproperties -ConnectionUri $uri -Force

    return $nic
}

function Add-SDNNetworkInterfaceIPConfiguration()
{
    param (
        [String] $uri,
        [String] $IpConfigName,
        [String] $ip,
        [string] $TenantSubnetRef,
        [psobject] $SDNNic
    )

    $ipconfiguration = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfiguration
    $ipconfiguration.resourceid = "IpConfig_$ip"
    $ipconfiguration.properties = new-object Microsoft.Windows.NetworkController.NetworkInterfaceIpConfigurationProperties
    $ipconfiguration.properties.PrivateIPAddress = $ip
    $ipconfiguration.properties.PrivateIPAllocationMethod = "Static"
    $ipconfiguration.properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
    $ipconfiguration.properties.subnet.ResourceRef = $TenantSubnetRef

    $SDNNic.properties.IpConfigurations += $ipconfiguration

    Write-SDNNestedLog "Adding VM=$VMName NIC=$($SDNNic.Name) Ipconfig=$ip to VMNic Object"

    $nic = New-NetworkControllerNetworkInterface -ResourceID $SDNNic.resourceid -Properties $SDNNic.properties -ConnectionUri $uri -Force
}

function Connect-SDNNetworkInterface()
{
    param (
        [String] $uri,
        [string] $VMName,
        [string] $SDNNicResourceId,
        [string] $SDNNicInstanceId
    )

    #Do not change the hardcoded IDs in this section, because they are fixed values and must not change.
    $FeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
                        
    $vmNics = Get-VMNetworkAdapter -VMName $VMName
                        
    $CurrentFeature = Get-VMSwitchExtensionPortFeature -FeatureId $FeatureId -VMNetworkAdapter $vmNics 

    Write-SDNNestedLog "Configuring SDNSwith Extension for $VMName vNIC"
        
    if ($null -eq $CurrentFeature)
    {
        $Feature = Get-VMSystemSwitchExtensionPortFeature -FeatureId $FeatureId

        $Feature.SettingData.ProfileId = "{$SDNNicInstanceId}"
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
        $CurrentFeature.SettingData.ProfileId = "{$SDNNicInstanceId}"
        $CurrentFeature.SettingData.ProfileData = 1
                
        Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $CurrentFeature -VMNetworkAdapter $vmNics
    }
    #Wait to be sure that Mac Address Allocation has been done
    do{
        $nic = Get-NetworkControllerNetworkInterface -ResourceID $SDNNicResourceId -ConnectionUri $uri
        Start-Sleep 1
    }while ( $null -eq $nic.properties.PrivateMacAddress );

    $vmNics | Set-VMNetworkAdapter -StaticMacAddress $nic.properties.PrivateMacAddress   
}

function New-SDNSoftwareLoadBalancerFrontendIpConfiguration()
{
    param (
        [String] $uri,
        [string] $ip,
        [string] $lbresourceId,
        [string] $ResourceId,
        [string] $VIPAllocationMethod,
        [string] $SubnetRef
    )

    $FrontEnd = new-object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfiguration
            
    $FrontEnd.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerFrontendIpConfigurationProperties
    $FrontEnd.resourceId = $ResourceId
    $FrontEnd.ResourceRef = "/loadBalancers/$lbresourceId/frontendIPConfigurations/$($FrontEnd.resourceId)"
    
    $FrontEnd.properties.PrivateIPAddress = $ip
    $FrontEnd.Properties.PrivateIPAllocationMethod = $VIPAllocationMethod

    $FrontEnd.Properties.Subnet = new-object Microsoft.Windows.NetworkController.Subnet
    $FrontEnd.Properties.Subnet.ResourceRef = $SubnetRef

    return $FrontEnd
}

function New-SDNSoftwareLoadBalancerBackendAddressPool()
{
    param (
        [String] $uri,
        [string] $lbresourceId,
        [string] $ResourceId
    )

    $BackEnd = new-object Microsoft.Windows.NetworkController.LoadBalancerBackendAddressPool
    $BackEnd.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerBackendAddressPoolProperties
    $BackEnd.resourceId = $ResourceId
    $BackEnd.ResourceRef = "/loadBalancers/$lbresourceId/backendAddressPools/$($BackEnd.resourceId)"

    return $BackEnd
}

function New-SDNLoadBalancingRule()
{
    param (
        [String] $LBRuleResourceId,
        [psobject] $FrontEnd,
        [psobject] $BackEnd,
        [hashtable] $vip
    )

    $lbrule = new-object Microsoft.Windows.NetworkController.LoadBalancingRule
    $lbrule.ResourceId = $LBRuleResourceId

    $lbrule.properties = new-object Microsoft.Windows.NetworkController.LoadBalancingRuleProperties    
    $lbrule.properties.frontendipconfigurations += $FrontEnd
    $lbrule.properties.backendaddresspool = $BackEnd 
    $lbrule.properties.protocol = $vip.Protocol
    $lbrule.properties.frontendPort = $vip.FrontendPort
    $lbrule.properties.backendPort = $vip.BackendPort
    $lbrule.properties.IdleTimeoutInMinutes = 4 

    return $lbrule
}

function New-SDNLoadBalancerOutboundNatRule()
{
    param (
        [String] $LBRuleResourceId,
        [psobject] $FrontEnd,
        [psobject] $BackEnd,
        [String] $Protocol
    )

    $onatrule = new-object Microsoft.Windows.NetworkController.LoadBalancerOutboundNatRule
    $onatrule.ResourceId = $LBRuleResourceId

    $onatrule.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerOutboundNatRuleProperties
    $onatrule.properties.frontendipconfigurations += $FrontEnd
    $onatrule.properties.backendaddresspool = $BackEnd
    $onatrule.properties.protocol = $Protocol

    return $onatrule
}
function New-SDNLoadBalancerProbe()
{
    param (
        [String] $ProbeName,
        [String] $lbresourceId,
        [hashtable] $vip,
        [int] $IntervalInSeconds,
        [int] $NumberOfProbes
    )

    $Probe = new-object Microsoft.Windows.NetworkController.LoadBalancerProbe
    $Probe.ResourceId = $ProbeName
    $Probe.ResourceRef = "/loadBalancers/$lbresourceId/Probes/$($Probe.ResourceId)"
   
    $Probe.properties = new-object Microsoft.Windows.NetworkController.LoadBalancerProbeProperties
    $Probe.properties.Protocol = $vip.Protocol
    $Probe.properties.Port = $vip.BackendPort
    #$Probe.properties.RequestPath = "/health.htm"
    $Probe.properties.IntervalInSeconds = $IntervalInSeconds
    $Probe.properties.NumberOfProbes = $NumberOfProbes

    return $Probe
}

function New-SDNSoftwareLoadBalancer()
{
    param (
        [String] $uri,
        [String] $lbresourceId,
        [psobject] $FrontEnd,
        [psobject] $BackEnd,
        [psobject] $lbrule,
        [psobject] $onatrule,
        [psobject] $Probe
    )

    Write-SDNNestedLog  "Pushing LoadBalancer $lbresourceId to $uri"

    #$lb = New-SDNSoftwareLoadBalancer $uri $lbresourceId $frontend $backendpool $lbrule $onatrule $probe 
    $lb = Get-NetworkControllerLoadBalancer -ConnectionUri $uri | ? ResourceId -eq $lbresourceId 
    if ( $lb )
    {
        $LoadBalancerProperties = $lb.properties
    }
    else 
    {
        $LoadBalancerProperties = new-object Microsoft.Windows.NetworkController.LoadBalancerProperties        
    }

    $LoadBalancerProperties.frontendipconfigurations += $FrontEnd
    $LoadBalancerProperties.backendAddressPools += $BackEnd
    if ( $lbrule )
    {
        $LoadBalancerProperties.loadbalancingRules += $lbrule
    }
    
    if ( $onatrule )
    {
        $LoadBalancerProperties.OutboundNatRules += $onatrule
    }

    if ( $Probe )
    {
        $LoadBalancerProperties.Probes += $Probe
        $LoadBalancerProperties.loadbalancingRules.properties.Probe += $Probe 
    }

    $lb = New-NetworkControllerLoadBalancer -ConnectionUri $uri -ResourceId $lbresourceId `
        -Properties $LoadBalancerProperties -Force -PassInnerException

    return $lb
}


function New-SDNiDNSConfiguration()
{
    param(
        [string] $ncrestfqdn,
        [string] $Domain,
        [string] $User,
        [string] $Password,
        [string] $DNS,
        [string] $DNSZone,
        [PSCredential] $credential
    )

    Write-SDNNestedLog  "Pushing iDNS config to $RestNameFQDN"

    $ncCreds=New-Object Microsoft.Windows.Networkcontroller.credentialproperties
    $ncCreds.type="usernamePassword"
    $ncCreds.username="$Domain\$User"
    $ncCreds.value=$Password
    $uri = "https://$ncrestfqdn"

    New-NetworkControllerCredential -ConnectionUri $uri -ResourceId "iDnsServer-Credential" -Properties $ncCreds -force

    $json = @"
{
    "properties": {
        "connections": [{
            "managementAddresses": ["$DNS"],
            "credential": {
                "resourceRef": "/credentials/iDnsServer-Credential"
            },
            "credentialType": "usernamePassword"
        }],
        "zone": "$DNSZone"
    }
}
"@

    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"
    $timeout = 10
    $method = "PUT"
    # Change ncrestfqdn appropriately if using outside of AzureStack
    $body = $json
    $uri = "https://$ncrestfqdn/networking/v1/iDnsServer/Configuration"
    #Use -Credential parameter instead of -UseDefaultCredentials if required.
    Invoke-WebRequest -Headers $headers -ContentType $content -Method $method -Uri $uri -Body $body -DisableKeepAlive -UseBasicParsing -Credential $credential

}

function New-DhcpServer()
{
    param (
        [string] $VMName,
        [string] $DNSfqdn,
        [string] $DNSMgmt,
        [string] $Subnet,
        [string] $router,
        [PSCredential] $credential
    )

    Invoke-Command -VMName $VMName -Credential $credential {
        $DNSfqdn  = $args[0]
        $DNSMgmt  = $args[1]
        $Subnet   = $args[2]
        $router   = $args[3]

        Write-Host  "Configuring DHCP Server on $ENV:COMPUTERNAME"

        netsh dhcp add securitygroups
        Restart-Service dhcpserver
        if ( $env:USERDOMAIN -ne $env:computername )
        {
            Add-DhcpServerInDC -DnsName $DNSfqdn -IPAddress $DNSMgmt
            Get-DhcpServerInDC
        }
        
        Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
        
        Set-DhcpServerv4DnsSetting -DynamicUpdates "Never"

        $Net=$Subnet.split("/")[0]
        $Cidr=$Subnet.split("/")[1]
        
        if ( $cidr -eq "24")
        {
            $Mask = "255.255.255.0"
        }

        $StartRange=$Net.split(".")[0]+"."+$Net.split(".")[1]+"."+$Net.split(".")[2]+".200"
        $EndRange=$Net.split(".")[0]+"."+$Net.split(".")[1]+"."+$Net.split(".")[2]+".210"

        $IntAlias=(Get-NetAdapter | Get-NetIpAddress -AddressFamily IPv4 | ? IpAddress -Match $($Net.split(".")[0]+"."+$Net.split(".")[1]+"."+$Net.split(".")[2])).InterfaceAlias

        if($IntAlias)
        {
            Get-NetAdapter | %{ Set-DhcpServerv4Binding -BindingState $false -InterfaceAlias $_.InterfaceAlias }
            Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias $IntAlias
        }
        Add-DhcpServerv4Scope -name "MGMT" -StartRange $StartRange -EndRange $EndRange -SubnetMask $Mask -State Active

        Set-DhcpServerv4OptionValue -OptionID 3 -Value $router -ScopeID $Net
        Set-DhcpServerv4OptionValue -OptionID 6 -Value $DNSMgmt -ScopeID $Net 
    } -ArgumentList $DNSfqdn, $DNSMgmt, $Subnet, $router
}   