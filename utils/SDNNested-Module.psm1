
function Write-SDNNestedLog 
{
    Param([String] $Message)

    $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
    $FormattedMessage = "[$FormattedDate] $Message"
    write-Host -ForegroundColor yellow $FormattedMessage

    $formattedMessage | out-file ".\SDNExpressLog.txt" -Append
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
        [PSCredential] $Credential,
        [Boolean] $Wait,
        [Int] $Seconds
    )

   Write-Host "$VMName is booting"
    
    if ( $Wait ){
        for($i=0;$i -lt $Seconds;$i++){Write-Host "." -NoNewline; Sleep 1; }
    }

    $loop = $true
    while ( $loop )
    {
        $result = Invoke-Command -VMName $VMName -Credential $Credential -ErrorAction SilentlyContinue  -ScriptBlock {
            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") 
            {
                "RebootPending"
            } 
            else
            {
                $env:COMPUTERNAME 
            }
        }
        
        if ( $result -eq $VMName ){ $loop = $false }
        if ( $result -eq "RebootPending" ){ $loop = $true }

        Start-Sleep -Seconds 10; 
       Write-Host "." -NoNewline 
    }
   Write-Host "[OK]"
}
function Add-UnattendFileToVHD {
    
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

    $TimeZone = "Central European Time"
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
    
function New-SdnNestedVm() {
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
        'KeyboardLayout'     = 'fr-fr';
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
        [hashtable] $TORrouter
    )

    #Adding RRAS and BGP config
    Invoke-Command -VMName $VMName -Credential $credential { 
        $TORrouter = $args[0]
        
        #Case where the VM is DC
        if ( get-service DNS -ErrorAction SilentlyContinue | Out-Null )
        {
            #Removing DNS registration on 2nd adapter
           Write-SDNNestedLog  "Configuring DNS server to only listening on mgmt NIC"   
            Get-NetAdapter "Ethernet 2" | Set-DnsClient -RegisterThisConnectionsAddress $false
            #Get-NetAdapter "Ethernet 2" | Set-DnsClientServerAddress -ServerAddresses "" 
            ipconfig /registerdns
            dnscmd /ResetListenAddresses "$($configdata.ManagementDNS)"
            Restart-Service DNS
        }
    }

    Add-WindowsFeatureOnVM $VMName $credential RemoteAccess

    Invoke-Command -VMName $VMName -Credential $credential { 
        $TORrouter = $args[0]
        
        Install-RemoteAccess -VpnType RoutingOnly

       Write-SDNNestedLog  "Configuring $env:COMPUTERNAME as TOR router" 
       Write-SDNNestedLog  "Configuring BGP router and BGP peers on $env:COMPUTERNAME"   

        Add-BgpRouter -BgpIdentifier $TORrouter.BgpRouter.RouterIPAddress -LocalASN $TORrouter.BgpRouter.RouterASN
        
        foreach ( $BgpPeer in $TORrouter.BgpPeers ) 
        {
            Add-BgpPeer -Name $BgpPeer.Name -LocalIPAddress $TORrouter.BgpRouter.RouterIPAddress -PeerIPAddress $BgpPeer.PeerIPAddress `
                -PeerASN $TORrouter.SDNASN -OperationMode Mixed -PeeringMode Automatic 
        }

        foreach ( $route in $TORrouter.StaticRoutes ) {
           Write-SDNNestedLog  "Adding Static routes $($route.Route) via $($route.NextHop)"
            $NextHopSplit = $($route.NextHop).split(".")
     
            $ifIndex = (Get-NetIPAddress | ? IPAddress -Match "$($NextHopSplit[0]).$($NextHopSplit[1]).$($NextHopSplit[2])").InterfaceIndex

            if ( $ifIndex ){
               Write-SDNNestedLog  "Adding Static route Dst=$($route.Route) NextHop=$($route.NextHop) ifIndex=$ifIndex"
                New-NetRoute -DestinationPrefix $route.Route -NextHop $route.NextHop -ifIndex $ifIndex
            }
            else { 
               Write-SDNNestedLog  "ERROR: Failded to add Static route Dst=$($route.Route) NextHop=$($route.NextHop) ifIndex=$ifIndex"
            }
        }
        add-content C:\ToR.txt ""
    } -ArgumentList $TORrouter

}

function Add-vNicIpConfig(){
    
    param(
        [psobject] $vNIC,
        [hashtable] $NetConfig
    )

    $NetAdapter = Get-NetAdapter | ? Name -Match $vNIC.Name

    $IpAddr = $NetConfig.IpAddress.split("/")[0]
    $PrefixLength = $NetConfig.IpAddress.split("/")[1]

    if( $NetAdapter )
    {
        if ( ! ($NetAdapter | Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -eq $IpAddr ) )
        {
           Write-SDNNestedLog "Configure Ip address/mask=$IpAddr/$PrefixLength Adapter=$($NetAdapter.Name) Host=$env:COMPUTERNAME"
            $NetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $IpAddr -PrefixLength $PrefixLength | Out-Null
           Write-SDNNestedLog "Configure DNS $($NetConfig.DNS) NetAdapter:$($NetAdapter.Name) Host=$env:COMPUTERNAME"
            $NetAdapter | Set-DnsClientServerAddress -ServerAddresses $NetConfig.DNS
        }
        else
        {
           Write-SDNNestedLog "$IpAddr already plumbed on Adapter=$($NetAdapter.Name) Host=$env:COMPUTERNAME"
        }
    }
    else {Write-SDNNestedLog  "ERROR: Failed to configure IpConfig and DNS vNIC=$($vNIC.Name) Host=$env:COMPUTERNAME" }

   Write-SDNNestedLog  "Configuring VLAN vNic=$($vNIC.Name) VLANID=$($NetConfig.VLANID) Host=$env:COMPUTERNAME"
    $vNIC | Set-VMNetworkAdapterVlan -Access -VlanId $NetConfig.VLANID

}

function Connect-HostToSDN()
{
    param(
        [array] $NICs,
        [String] $VMswitch,
        [hashtable] $NetRoute
    )

    foreach($NIC in $NICs)
    {

        if ( !(  Get-VMNetworkAdapter -ManagementOS -Name $NIC.Name -SwitchName $VMswitch -ErrorAction SilentlyContinue ) )
        {
            Write-SDNNestedLog  "Adding vNIC=$($NIC.Name) on Host=$env:COMPUTERNAME"
            Add-VMNetworkAdapter -ManagementOS -Name $NIC.Name -SwitchName $VMswitch 
        }
        while ( !( Get-VMNetworkAdapter -ManagementOS -Name $NIC.Name -SwitchName $VMswitch -ErrorAction Ignore)){ sleep 1}
        
        $vNIC =  Get-VMNetworkAdapter -ManagementOS -Name $NIC.Name -SwitchName $VMswitch
        if( $vNIC ) 
        { 
            Add-vNicIpConfig $vNIC $NIC
        }
    }

    if ( ! (Get-NetRoute -DestinationPrefix  $NetRoute.Destination ) )
    {
        $NextHopSplit = $($NetRoute.NextHop).split(".")
        $ifIndex = (Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -Match "$($NextHopSplit[0]).$($NextHopSplit[1]).$($NextHopSplit[2])").InterfaceIndex

        if ( $ifIndex ){
            New-NetRoute -AddressFamily "IPv4" -DestinationPrefix $NetRoute.Destination -NextHop $NetRoute.NextHop -InterfaceIndex $IfIndex | Out-Null
            Write-SDNNestedLog  "NetRoute SDN VIP pool=$($NetRoute.Destination) is added on $env:computername"
        }
        else  {Write-SDNNestedLog  "ERROR: NetRoute=$($NetRoute.Destination) on $env:computername to reach SDN VIP has not been added" }
    }
    else{ Write-SDNNestedLog "NetRoute SDN VIP pool=$($NetRoute.Destination) already present on $env:computername" }
}

function Add-WindowsFeatureOnVM() {
    param(
        [String] $VMName,
        [PSCredential] $credential,
        [String[]] $FeatureList
    )

    $SecondsToWait=0

    foreach ($feature in $FeatureList) {
        Write-Host "Installing Windows Feature $feature on $COMPUTERNAME"
        Invoke-Command -VMName $VMName -Credential $credential {
            $feature=$args[0]
            if ( $feature -eq "RemoteAccess"){ Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools | Out-Null }
            else { Install-WindowsFeature -Name $feature -IncludeManagementTools | Out-Null }
            
        } -ArgumentList $feature
        $SecondsToWait+=5
    }

    Write-SDNNestedLog  "Rebooting $VMName"     
    Invoke-Command -VMName $VMName -Credential $credential { 
        Restart-Computer -Force 
    }
    
    WaitLocalVMisBooted $VMName $credential $true $SecondsToWait
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
    
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
       Write-SDNNestedLog  "Installing AD-DS on vm $env:COMPUTERNAME"
        Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools | Out-Null
        
        $params = @{
            DomainName                    = $args.DomainName
            DomainMode                    = $args.DomainMode
            SafeModeAdministratorPassword = $args.SafeModeAdministratorPassword
        }
       Write-SDNNestedLog  "Installing ADDSForest on vm $env:COMPUTERNAME"
        Install-ADDSForest @params -InstallDns -Confirm -Force | Out-Null
        #
    } -ArgumentList $paramsDeployForest
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

    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        $params = @{
            DomainName                    = $args.DomainName
            Credential                    = $args.Credential
        }

       Write-SDNNestedLog  "Promote vm $env:COMPUTERNAME as DC to domain $($params.DomainName)"
        Install-ADDSDomainController @params -InstallDns -Confirm -Force | Out-Null
    } -ArgumentList $paramsAddDc
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
        New-VHD -Path "$LocalVMPath\$VMNAme-$DiskNameStr-$i.vhdx" -SizeBytes $DiskSize -Dynamic | Out-Null
        Add-VMHardDiskDrive -Path "$LocalVMPath\$VMNAme-$DiskNameStr-$i.vhdx" -VMName $VMName -ControllerType SCSI | Out-Null
    }   
}

function New-SDNS2DCluster {
    param (
        [String[]] $Nodes,
        [PSCredential] $credential,
        [String] $IpAddress,
        [String] $ClusterName
    )

   Write-SDNNestedLog "S2DCONFIG: Cleaning Drives"
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

    Invoke-Command -VMName $Nodes[0] -ArgumentList $Nodes, $IpAddress, $ClusterName -Credential $credential -ScriptBlock {
         
        $ClusterNodes = $args[0]
        $ClusterIP = $args[1]
        $ClusterName = $args[2]

        # Create S2D Cluster
        Write-Verbose "Creating Cluster: SDNCLUSTER"
        Import-Module FailoverClusters 

        #Test-Cluster –Node $ClusterNodes[0], $ClusterNodes[1] –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"

        # Create Cluster
        New-Cluster -Name $ClusterName -Node $ClusterNodes -StaticAddress $ClusterIP -NoStorage | Out-Null

        # Invoke Command to enable S2D on SDNCluster        
        Enable-ClusterS2D -CacheState Disabled -AutoConfig:0 -SkipEligibilityChecks -Confirm:$false | Out-Null

        $params = @{
                StorageSubSystemFriendlyName = "*Clustered*"
                FriendlyName                 = 'SDN_S2D_Storage'
                ProvisioningTypeDefault      = 'Fixed'
            }

        New-StoragePool @params -PhysicalDisks (Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true }) | Out-Null

        Get-PhysicalDisk | Where-Object  MediaType -eq "UnSpecified" | Set-PhysicalDisk -MediaType HDD | Out-Null

        $params = @{  
            FriendlyName            = 'S2D_CSV1' 
            FileSystem              = 'CSVFS_ReFS'
            StoragePoolFriendlyName = 'SDN_S2D_Storage'
            PhysicalDiskRedundancy  = 1    
        }

        New-Volume @params -UseMaximumSize | Out-Null

        # Set Virtual Environment Optimizations
        Get-storagesubsystem clus* | set-storagehealthsetting -name “System.Storage.PhysicalDisk.AutoReplace.Enabled” -value “False”
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530
    } | Out-Null
}