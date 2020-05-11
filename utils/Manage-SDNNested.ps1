[CmdletBinding(DefaultParameterSetName = "NoParameters")]
param(
    [Parameter(Mandatory = $false)] 
    [ValidateSet("Init","HostAgentRestart","GatewayFailover",
                 "UpdateHostSmbGlobalMapping","RestartLAB","StopLAB","StartLAB")] [String] $Action = "Init"
) 

function WaitVMs()
{
    param(
        [string[]] $VMs,
        [PSCredential] $Credential
    )    
    #Checking that we can access SDN-HOST
    $loop = $true
    $cpt=0

    foreach ( $VM in $VMs)
    {
        Write-Host -ForegroundColor Yellow "Checking that VM VMName=$VM is accessible via PS Remote"
        while ( $loop )
        {
            #FQDN Case no PS Direct
            if ( $VM -match "\.")
            {
                $res = Invoke-Command $VM -credential $Credential -ErrorAction SilentlyContinue { $env:computername }           
                $res = if ( $VM -match $res){ $VM }else{ $res }
            }
            else 
            {
                $res = Invoke-Command  -VMName $VM -credential $Credential -ErrorAction SilentlyContinue { $env:computername }                
            }
            
            $loop = if ( $res -eq $VM){ $False } else { $True }
            
            if ( $loop )
            { 
                Write-Host "Sleeping 30 secs before retrying to connect...."
                Start-Sleep 30
            }
        }
        $cpt++
        if ( $cpt -eq $VMs.Count) { break;}
        $loop = $true
    }   
    Sleep 5
}

function StartAllVMs()
{
    param(
        [string] $HypvHost,
        [PSCredential] $Credential
    )    

    $ScriptBlock = {   
        $VMs = Get-VM -ErrorAction SilentlyContinue

        foreach( $Current in $VMs)
        {
            #If state is Saved - Then stop it before start it
            $Current | Where-Object State -eq Saved |  ForEach-Object {
                Write-Host -ForegroundColor Yellow "Stopping previously saved VM VMName=$($Current.Name)"
                stop-vm $current.name -force
            }
        
            $Current | Where-Object State -ne Running |  ForEach-Object {
                Write-Host -ForegroundColor Green "Starting VM VMName=$($Current.Name)"
                start-vm $current.name
            }
        }
    }   

    if ( $HypvHost -ne $env:computername)
    {
        $parameters = @{
            credential  = $Credential
            VMName      = $HypvHost 
            ScriptBlock = $ScriptBlock
        }
        Invoke-Command  @parameters -ErrorAction SilentlyContinue
    }
    else
    {
        Invoke-Command $ScriptBlock
    }
}

function HostAgentRestart()
{
    param(
        [string[] ] $HypvHosts,
        [PSCredential] $Credential
    )    

    foreach ( $SDNHost in $HypvHosts)
    {
        Invoke-Command  -VMName $SDNHost -credential $SDNAdmin -ErrorAction SilentlyContinue {
            Write-Host -ForegroundColor Yellow "Restarting NcHostAgent and SlbHostAgent on VMName=$env:COMPUTERNAME"
            Restart-Service NcHostAgent -Force
            Restart-Service SlbHostAgent
        }
    }
}

Write-Host -ForegroundColor Red "###############################################################################"
Write-Host -ForegroundColor Red "###############################################################################"
Write-Host -ForegroundColor Red "###############################################################################"
Write-Host -ForegroundColor Red "########                                                               ########"
Write-Host -ForegroundColor Red "########        DO NOT CLOSE THIS WINDOW or DO NOT CLICK ON IT!        ########"
Write-Host -ForegroundColor Red "########                                                               ########"
Write-Host -ForegroundColor Red "###############################################################################"
Write-Host -ForegroundColor Red "###############################################################################"
Write-Host -ForegroundColor Red "###############################################################################"
Write-Host
Write-Host
Write-Host -ForegroundColor Yellow "This helper script will help to bring SDN VMAS LAB back to life !"

#Getting SDN LAB admin credantial and local VM admin credential
$SDNAdmin = get-credential -Message "Please provide SDN LAB admin credential" SDN\Administrator
$LocalAdmin = get-credential -Message "Please provide local VMS admin credential" Administrator

$SDNHosts   = @("SDN-HOST01","SDN-HOST02")

#Name has to be FQDN
$SDNToR     = "SDN-DC01.SDN.LAB"
$SDNMUXes   = @("SDN-MUX01.SDN.LAB","SDN-MUX02.SDN.LAB")
$SDNNCs     = @("SDN-NC01.SDN.LAB")

# Gateway failover case
if ( $Action -eq "GatewayFailover" )
{
    #Checking which GW is active and restart it!!!
    #Better approach would be using REST API but this is not a big program....
    $ActiveGw= invoke-command -VMname $SDNHosts[0] -Credential $SDNAdmin { 
        $Rest=(Get-ItemProperty "hklm:\system\currentcontrolset\services\nchostagent\parameters").PeerCertificateCName; 
        $Rest="https://$Rest";

        $Gw=(Get-NetworkControllerGateway -ConnectionUri $Rest)
        
        $Gw | ForEach-Object{ 
            if ( $_.properties.state -eq "Active")
            { 
                $_.resourceId 
            } 
        } 
    }   

    if ( $null -eq $ActiveGw)
    {
        $ActiveGW = Invoke-Command $SDNToR -Credential $SDNAdmin -ea SilentlyContinue { 
            Get-BgpPeer | Where-Object PeerName -Match GW | Where-Object ConnectivityStatus -eq Connected
        } 

        if ( $ActiveGW.PeerName )
        { 
            $GW=$ActiveGW.PeerName
            Write-Host -ForegroundColor Yellow "Found active gateway from ToR $SDNToR..."
            $ActiveGW="$GW.SDN.LAB"
        }
        else { Write-Host -ForegroundColor Yellow "Cannot find the active GW from ToR router peering!" }
    }

    if ( $ActiveGW )
    {
        Write-Host -ForegroundColor Yellow "Restarting $ActiveGW....."
        Invoke-Command $ActiveGw -Credential $SDNAdmin -ea SilentlyContinue { Restart-Computer -Force } 
    }
    else { Write-Host -ForegroundColor Yellow "Cannot find the active GW!" }

}
# SDN Host's agent restart
elseif( $Action -eq "HostAgentRestart" ) 
{
    HostAgentRestart -Credential $SDNAdmin -HypvHosts $SDNHosts
}
# Reconfigure SMB Global mapping since the VMAS vm's name has been changed
elseif( $Action -eq "UpdateHostSmbGlobalMapping" )
{ 
    #Update SMB Global Mapping
    $VMASUser = get-credential -Message "Please provide VMAS VM credential" VMASUser

    foreach ( $SDNHost in $SDNHosts)
    {
        
        Invoke-Command  -VMName $SDNHost -credential $SDNAdmin -ErrorAction SilentlyContinue {
            $cred = $args[0]

            $LocalVMName = (get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName")
            Write-Host -ForegroundColor Yellow "VM=$env:computername recreating SMB GlobalMapping to SDNNested folder on VMAS VM:$LocalVMName"
            Get-SmbGlobalMapping | Remove-SmbGlobalMapping -Force

            Write-Host  "$env:COMPUTERNAME :Mapping SMBSHare from \\$LocalVMName\template to Z:"
                    
            NEw-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$LocalVMName\Template"  -Credential $Cred -Persistent $true
        } -ArgumentList $VMASUser
    }
}
# Default Mode.... Should bring everything UP and running
elseif( $Action -eq "Init" )
{
    #Cheking if VMMS is running
    if ( (Get-Service vmms).status -ne "Running")
    {
        Restart-Service Winmgmt -Force
        Start-Sleep 10
        Start-Service vmms
    }

    StartAllVMs -Credential $SDNAdmin -HypvHost $env:computername

    WaitVMs -Credential $SDNAdmin -VMs $SDNHosts

    Write-Host -ForegroundColor Green "SDN Hosts are accessible via PS Remote"
    foreach ( $SDNHost in $SDNHosts)
    {
        StartAllVMs -Credential $SDNAdmin -HypvHost $SDNHost     
    }

    HostAgentRestart -Credential $SDNAdmin -HypvHosts $SDNHosts

    #Caching creds to local key vault
    $SDNDomainPassword = $SDNAdmin.GetNetworkCredential().Password
    $SDNDomainUsername = $SDNAdmin.GetNetworkCredential().UserName
    Invoke-Expression -Command "cmdkey /add:*.SDN.LAB /user:$SDNDomainUsername /pass:$SDNDomainPassword" | Out-Null
    
    Write-Host -ForegroundColor yellow "SDN creds have been cached so you might be able to add SDN-HOST thouhg Hypv Mgmt Console
        or reach SDN VMs via PSSession or in WAC w/o being prompted. Condition is to user FQDN notation."

    #Start Hypv mgmt console
    & virtmgmt.msc
    Write-Host "Starting Hypv Mgmt Console. You can add SDN-HOST01.SDN.LAB and SDN-HOST02.SDN.LAB to the Hypv Manager !"

    Write-Host "Starting Internet browser. Please think to pin each tab as favorite for convenience!"
    Write-Host "It might take some time to have tenant Public VIP reachable and all the SDN stack UP and running."
    Write-Host "The best thing to do now is to wait up to 15/30 min!"

    Start-Sleep 5

    $URIs = @("http://41.40.40.8","http://41.40.40.9","https://localhost","https://github.com/ViDou83/SDNNested")
    $Path = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    #Starting Edge 
    if ( Test-Path $Path)
    {
        foreach ($URI in $URIs)
        {
            & $Path $URI
        }
    }
}
# Restart all SDN VM's and SDN Hosts
elseif($Action -eq "RestartLAB" )
{
    Write-Host -ForegroundColor yellow "Restarting all SDN VMs"
    foreach ( $SDNHost in $SDNHosts)
    {
        Invoke-Command  -VMName $SDNHost -credential $SDNAdmin -ErrorAction SilentlyContinue {
            Get-VM | Stop-VM -Force 
            Restart-Computer -Force
        }
    }

    WaitVMs -Credential $SDNAdmin -VMs $SDNHosts

    foreach ( $SDNHost in $SDNHosts)
    {       
        StartAllVMs -Credential $SDNAdmin -HypvHost $SDNHost
    }
}
# Restart all SDN VM's and SDN Hosts
elseif($Action -eq "StopLAB" )
{
    Write-Host -ForegroundColor yellow "Stoping all SDN VMs"
    foreach ( $SDNHost in $SDNHosts)
    {
        Invoke-Command  -VMName $SDNHost -credential $SDNAdmin -ErrorAction SilentlyContinue {
            Get-VM | Stop-VM -Force 
        }
    }

    #Stopping all VMs .. DC, Extenral GW and SDn-HOsts
    Get-VM | Stop-VM -Force
}
# Restart all SDN VM's and SDN Hosts
elseif($Action -eq "StartLAB" )
{
    Write-Host -ForegroundColor yellow "Starting all SDN VMs"
    
    #Stopping all VMs .. DC, Extenral GW and SDn-HOsts
    Get-VM | Start-VM

    WaitVMs -Credential $SDNAdmin -VMs $SDNHosts

    foreach ( $SDNHost in $SDNHosts)
    {
        StartAllVMs -Credential $SDNAdmin -HypvHost $SDNHost
    }
}
