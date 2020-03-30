<#
.SYNOPSIS
    The Script used to collect SDN Envrionment Logs for Windows Server SDN Deployment
.DESCRIPTION
    Script to be executed from a Jumpbox that have access to NC Rest URI and the PowerShell Remoting needed to collect logs on NC, MUX, Gateway and SDN Host
.EXAMPLE
    Scenario 1: Collect Infra Logs not include Hosts
    PS C:\> SDNLogCollect.ps1 -NCVM <NCVMName>
    The most common usage. Specify one of the NC VM and collect Logs from NC, MUX and Gateway VMs. 

    Scenario 2: Include SDN Hosts Logs
    Step 1: Define the SDN Hosts array that include all Hosts need data collection
    PS C:\> $SDNHosts = $("host1","host2")
    Step 2: Start the Hosts trace, 
    PS C:\> SDNLogCollect.ps1 -StartSDNHostTrace -SDNHosts $SDNHosts
    If you want to include VFP Logs and Network Traces on Hosts, use -InccludeVfp switch
    PS C:\> SDNLogCollect.ps1 -StartSDNHostTrace -SDNHosts $SDNHosts -IncludeVfp
    Step 3: Stop the Hosts trace after issue reproduced, specificy one of the NC VM Name also to collect infra logs together.
    PS C:\> SDNLogCollect.ps1 -StopSDNHostTrace -SDNHosts $SDNHosts -NCVMName <One of the NC VM Name>
.PARAMETER NCVMName 
    [REQUIRED]
    Specify one of the NC VM name in NC Cluster

.PARAMETER OutputPath
    [REQUIRED]
    Specify the path you want to save the logs to. Defaults to current folder

.PARAMETER StartSDNHostTrace
    [OPTIONAL]
    Used to start the SDN Host trace. $SDNHosts is required.

.PARAMETER StopSDNHostTrace
    [OPTIONAL]
    Used to stop the SDN Host trace. $SDNHosts is required.
       
    
.PARAMETER IncludeVfp
    [OPTIONAL]
    Used together with StartSDNHostTrace. No need to specify when StopSDNHostTrace. 
    When specified, this script will collect Network Traces include VFP ETL on Hosts. The log collection time will take longer.
       
.PARAMETER SDNHosts
    [OPTIONAL]
    Used to specificy the SDN Hosts Array that you want Start/Stop logs. Required when StartSDNHostTrace/StopSDNHostTrace specified.
    
.NOTES
    Author: Luyao Feng (luyaof@microsoft.com)
#>

Param(
    [int]$LastInNum,
    [int]$LastInMin,
    [switch]$All,
    [String]$NCVMName,
    [String]$OutputPath,
    [switch]$StartSDNHostTrace,
    [switch]$StopSDNHostTrace,
    [switch]$IncludeVfp,
    [String[]]$SDNHosts

)

function Write-Log(
    [String]$Message,
    [ValidateSet("Info","Warning","Error")]
    [String]$Type = "Info")
{
    $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
    $FormattedMessage = "[$FormattedDate] [$Type] $Message"
    $messageColor = "Green"
    Switch($Type)
    {
        "Info"{ $messageColor = "Green"}
        "Warning"{$messageColor = "Yellow"}
        "Error"{$messageColor = "Red"}
    }
    Write-Host -ForegroundColor $messageColor $FormattedMessage

    $formattedMessage | out-file "$OutputPath\SDNLogCollectLog.txt" -Append
}

function Get-SdnResources([String]$NcUri, [String]$OutputFolder, [pscredential]$Cred) 
{
    $OutputFolder = "$OutputFolder\SDNResources"
    # Gather Network Controller resources
    Write-Log -Message "Gathering SDN configuration details. Results saved to $OutputFolder" 
    New-Item -Path "$OutputFolder" -ItemType Directory -Force | Out-Null
    [array]$SDNResources="AccessControlLists","Credentials","GatewayPools","Gateways","LoadBalancerMuxes","LoadBalancers","LogicalNetworks","MacPools","NetworkInterfaces","PublicIPAddresses","Servers","RouteTables","VirtualGateways","VirtualNetworks","VirtualServers","iDNSServer/configuration","LoadBalancerManager/config","virtualNetworkManager/configuration","serviceInsertions"
    foreach ($resource in $SDNResources){
        Try {
            Invoke-RestMethod -Uri "$NcUri/networking/v1/$resource" -Method Get -UseDefaultCredentials | ConvertTo-Json -Depth 100 | Out-File "$OutputFolder\$resource.json".Replace("/","_")
        }
        Catch {
            if($_.Exception.Response.StatusCode.Value__ -ne 404)
            {
                Write-Log -Message "$($_.Exception) 
                at $($_.Exception.Response.ResponseUri.AbsoluteUri)" -Type "Error"
            }else
            {
                Write-Log "$resource not found" -Type "Warning"
            }
        }
    }
}

Function Start-NCImosDump([String]$NCUri)
{
	Import-Module NetworkController
	
	Write-Log "Triggering IMOS Dump"
	$state=New-Object Microsoft.Windows.NetworkController.NetworkControllerStateProperties
	$ncStateResult = Invoke-NetworkControllerState -ConnectionUri $NCUri -Properties $state -Force
	
    $ncState = Invoke-RestMethod -Uri "$($NCUri)/networking/v1/diagnostics/networkcontrollerstate" -UseDefaultCredentials
    $timeout = 300
    Write-Log "Waiting for IMOS Dump finish"
	while($timeout -gt 0)
	{
		$ncState = Invoke-RestMethod -Uri "$($NCUri)/networking/v1/diagnostics/networkcontrollerstate" -UseDefaultCredentials
		if($ncState.properties.provisioningState -ne "Updating")
		{
			break
		}
		Start-Sleep -s 10
		$timeout = $timeout - 10
	}
	Write-Log "IMOS Dump finished status: $($ncState.properties.provisioningState)"
}

Function Get-NCImosDump([String]$NCVMName, [String]$OutputPath)
{
    Write-Log "Getting IMOS Dump via NCURI: $($NcUri)"
    $NCVMs = Get-NetworkControllerNode -ComputerName $NCVMName
    # Cleanup the existing IMOS Dump folder to generate a new one

    Invoke-Command -ComputerName $NCVMs.Server -ScriptBlock{
        Write-Host "[$(HostName)]Cleaning IMOS DB folder"
        Get-ChildItem -Path "C:\Windows\tracing\SDNDiagnostics\NetworkControllerState" | Remove-Item -Force
    }

    Start-NCImosDump -NCUri $NcUri
    
    foreach($NCVM in $NCVMs)
    {
        Write-Log "Getting IMOS dump from $($NCVM.Server)"
        $RemotePathToCopy = "\\$($NCVM.Server)\c$\Windows\Tracing\SDNDiagnostics\NetworkControllerState\*"
        New-Item "$OutputPath\NetworkControllerState" -ItemType Directory -Force | Out-Null
       	Copy-Item -Path $RemotePathToCopy -Destination "$OutputPath\NetworkControllerState" -Recurse
    }
}

Function Get-NCLogInMin([int]$LastInMin, [String]$NCVMName, [String]$OutputPath)
{
    $LatestTime = (Get-Date).AddMinutes(-$latestTimeInMins)
    $LatestTime = $LatestTime.ToUniversalTime()

    $NCVMs = Get-NetworkControllerNode -ComputerName $NCVMName
    foreach($NCVM in $NCVMs)
    {
        Write-Log "Getting NC ETL logs from $($NCVM.Server)"

        $ToCopy = Invoke-Command -ComputerName $($NCVM.Server) -ArgumentList $LatestTime -ScriptBlock{
        Param(
            [DateTime]$LatestTime
        )
            $logs = Get-ChildItem -Path "C:\Windows\Tracing\*.log"
            $etls = Get-ChildItem -Path "C:\Windows\Tracing\SDNDiagnostics\Logs" | sort LastWriteTime -Descending
            $EtlToCopy = @()
            foreach($etl in $etls)
            {
                $EtlToCopy += $etl.Name
                if($etl.LastWriteTimeUtc -le $LatestTime)
                {
                    return $EtlToCopy
                }
           
            }
        }

        Write-Log "Invoke-Command done for $($NCVM.Server)"
        $RemotePathToCopy = "\\$($NCVM.Server)\c$\Windows\Tracing\SDNDiagnostics\Logs\"


        $NCVMFolder = New-Item -ItemType Directory  -Path "$OutputPath\$($NCVM.Server)\ETL"
        foreach($Etl in $ToCopy)
        {
            Copy-Item -Path $RemotePathToCopy\$Etl -Destination "$($NCVMFolder.FullName)\$Etl"
        }
    }
}


Function Get-NCLogInNumber([int]$LastInNum, [String]$NCVMName, [String]$OutputPath)
{
   
    $NCVMs = Get-NetworkControllerNode -ComputerName $NCVMName
    foreach($NCVM in $NCVMs)
    {
        Write-Log "Getting logs from $($NCVM.Server)"

        $ToCopy = Invoke-Command -ComputerName $($NCVM.Server) -ArgumentList $LastInNum -ScriptBlock{
        Param(
            [int]$LastInNum
        )
            $logs = Get-ChildItem -Path "C:\Windows\Tracing\*.log"
            $etls = Get-ChildItem -Path "C:\Windows\Tracing\SDNDiagnostics\Logs" -Filter "*ETL*" | sort LastWriteTime -Descending
            $EtlToCopy = @()
            foreach($etl in $etls)
            {
                if ( $etl.name -notmatch "cab")
                {
                    Write-Log "Convert ETL file $($etl.FullName) before copying it!"
                    netsh trace convert $etl.FullName "$($etl.FullName).TXT" | Out-Null
                    if ( Test-Path "$($etl.FullName).TXT" )
                    {
                        $EtlToCopy += "$($etl.Name).TXT"
                    }   
                }

                $EtlToCopy += $etl.Name
                if($LastInNum -gt 0){
                    $LastInNum --
                }
                if($LastInNum -eq 0)
                {
                    return $EtlToCopy
                }
           
            }

            return $EtlToCopy
        }

        Write-Log "Invoke-Command done for $($NCVM.Server)"
        $RemotePathToCopy = "\\$($NCVM.Server)\c$\Windows\Tracing\SDNDiagnostics\Logs\"

        $NCVMFolder = New-Item -ItemType Directory  -Path "$OutputPath\$($NCVM.Server)\ETL"
        foreach($Etl in $ToCopy)
        {
            Copy-Item -Path $RemotePathToCopy\$Etl -Destination "$($NCVMFolder.FullName)\$Etl"
        }
    }
}

Function Get-NCClusterInfo([String]$NCVMName, [String]$OutputPath)
{
    Write-Log "Getting NC Cluster Info"
    New-Item -Path "$OutputPath\NCClusterInfo" -ItemType Directory -Force | Out-Null
    $OutputPath = "$OutputPath\NCClusterInfo"
    $ncPSSession = New-PSSession -ComputerName $NCVMName
    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkControllerReplica
    }| Out-File -FilePath "$OutputPath\GetNetworkControllerReplica.txt" 

    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkController
    } | Out-File -FilePath "$OutputPath\GetNetworkController.txt" 

    Invoke-Command -Session $ncPSSession -ScriptBlock{
        Get-NetworkControllerNode
    } | Out-File -FilePath "$OutputPath\GetNetworkControllerNode.txt" 

    
    $sfClusterInfo = Invoke-Command -Session $ncPSSession -ScriptBlock{
        Connect-ServiceFabricCluster | Out-Null
        Get-ServiceFabricClusterHealth | Select-Object AggregatedHealthState, NodeHealthStates, ApplicationHealthStates | ft -AutoSize
        Get-ServiceFabricNode | Format-Table NodeName, IpAddressOrFQDN, NodeStatus, NodeUpTime, HealthState, ConfigVersion, CodeVersiom, FaultDomain, UpgradeDomain -AutoSize | Out-String -Width 4096
        Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController | ft ApplicationName, ApplicationStatus, HealthState -AutoSize
        Get-ServiceFabricService -ApplicationName fabric:/NetworkController | ft ServiceName, ServiceStatus, HealthState -AutoSize
        Get-ServiceFabricService -ApplicationName fabric:/System | ft ServiceName, ServiceStatus, HealthState -AutoSize
    }

    $sfClusterInfo | Out-File -FilePath "$OutputPath\ServiceFabricHealth.txt" 

}
Function Start-SDNHostLogs([String[]]$SDNHosts, [bool]$IncludeVfp)
{
    if($SDNHosts.Count -gt 0){
        Invoke-Command -ComputerName $SDNHosts -ScriptBlock{
            Param(
                [bool]$IncludeVfp
            )

            New-item -Path c:\SDNHostTrace -ItemType Directory -Force

            logman create trace "ncha" -ow -o c:\SDNHostTrace\ncha.etl -p "{28F7FB0F-EAB3-4960-9693-9289CA768DEA}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
            logman update trace "ncha" -p "{A6527853-5B2B-46E5-9D77-A4486E012E73}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{dbc217a8-018f-4d8e-a849-acea31bc93f9}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{41DC7652-AAF6-4428-BBBB-CFBDA322F9F3}" 0xffffffffffffffff 0xff -ets
            logman update trace "ncha" -p "{F2605199-8A9B-4EBD-B593-72F32DEEC058}" 0xffffffffffffffff 0xff -ets
            
            logman create trace "vm_dv" -ow -o c:\SDNHostTrace\vm_dv.etl -p "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
            logman update trace "vm_dv" -p "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" 0xffffffffffffffff 0xff -ets

            logman create trace "slbha" -ow -o c:\SDNHostTrace\slbha.etl -p "{2380c5ee-ab89-4d14-b2e6-142200cb703c}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

            
            if($IncludeVfp){
                #Start the VFP related trace
                
                logman create trace "vfp" -ow -o c:\SDNHostTrace\vfpext.etl -p "{9F2660EA-CFE7-428F-9850-AECA612619B0}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
                logman update trace "vfp" -p "Microsoft-Windows-Hyper-V-Vmswitch" 0xffffffffffffffff 0xff -ets
                logman update trace "vfp" -p "Microsoft-Windows-NDIS-PacketCapture" 0xffffffffffffffff 0xff -ets

                netsh trace start capture=yes overwrite=yes maxsize=2048 tracefile=c:\SDNHostTrace\host.etl scenario=virtualization capturetype=both  
            }
            Write-Host "Started SDN Host Trace at $(HostName)"
        } -ArgumentList $IncludeVfp
    }else {
        Write-Error "No SDN Hosts Specified"
        return
    }
}

Function Stop-SDNHostLogs([String[]]$SDNHosts, [String]$OutputPath, [bool]$IncludeVfp)
{
    if($SDNHosts.Count -gt 0){
        Invoke-Command -ComputerName $SDNHosts -ScriptBlock{
            param(
                [bool]$IncludeVfp
            )
            Write-Host "Stopping SDN Host Trace at $(HostName)"
            logman stop "ncha" -ets
            logman stop "vm_dv" -ets
            logman stop "slbha" -ets

            if($IncludeVfp){
                #Stop VFP related trace
                logman stop "vfp" -ets
                netsh trace stop
            }
        } -ArgumentList $IncludeVfp
    }else
    {
        Write-Error "No SDN Hosts Specified"
        return
    }
}

# Function to collect logs from Infra Nodes. This used to collect static logs only
Function Get-SdnInfraNodeLogs(
    [Parameter(Mandatory = $true)]
    [String[]] $InfraNodes,
    [Parameter(Mandatory = $true)]
    [ValidateSet("NC","MUX","GW")]
    [String]$Role,
    [Parameter(Mandatory = $true)]
    [String]$OutputFolder
)
{
    $DataCollectionDir = "C:\Temp\CSS_SDN"
    $InfraNodeSessions = @()
    $FromDate = (Get-Date).AddHours(-4)
    $FromDateSf = (Get-Date).AddHours(-1)
    $FromDateNc = (Get-Date).AddHours(-8)
    Write-Log -Message "Creating remote sessions to Infra Nodes: $InfraNodes"
    foreach ($InfraNode in $InfraNodes){
        Try {
            $InfraNodeSessions += New-PSSession -ComputerName $InfraNode -ErrorAction Stop
        }
        Catch {
            Write-Log -Message "$_" -Type Error
            continue
        }
    }

    # Gather data from data nodes
    Write-Log -Message "Gathering $Role Logs from $($InfraNodeSessions.ComputerName)"
    $InvokeRemoteJob = Invoke-Command -Session $InfraNodeSessions -ScriptBlock {
        Param(
            [String] $Role,
            [String] $DataCollectionDir
        )
        function Write-Log(
            [String]$Message,
            [ValidateSet("Info","Warning","Error")]
            [String]$Type = "Info")
        {
            $FormattedDate = date -Format "yyyyMMdd-HH:mm:ss"
            $FormattedMessage = "[$FormattedDate] [$Type] [$(HostName)] $Message"
            $messageColor = "Green"
            Switch($Type)
            {
                "Info"{ $messageColor = "Green"}
                "Warning"{$messageColor = "Yellow"}
                "Error"{$messageColor = "Red"}
            }
            Write-Host -ForegroundColor $messageColor $FormattedMessage
        
            $formattedMessage | out-file "$DataCollectionDir\SDNLogCollectLog.txt" -Append
        }
          New-Item -Path "$DataCollectionDir\SDNLogCollectLog.txt" -Force
        # Remove the temp local directory if existed to cleanup old 
        if(Test-Path $DataCollectionDir){
            Write-Host "[$(HostName)] Log path $DataCollectionDir existed, remove the old logs and recreate"
            Remove-Item -Path $DataCollectionDir -Recurse -Force
        }
        
        Write-Host "[$(HostName)] Creating Folder $DataCollectionDir"
        # Create local directory now
        New-Item -Path "$DataCollectionDir" -ItemType Directory | Out-Null
        New-Item -Path "$DataCollectionDir\SDNLogCollectLog.txt" -Force
        
        Write-Log "Started Data Collection"

        # Collect general logs for any role
        $folders = Get-ChildItem -Path "C:\Windows\Tracing" -Recurse -Directory | Where-Object {$_.Name -ne "NetworkControllerState" -and $_.Name -ne "CrashDumps" -and $_.name -ne "AutoBackups"}
        $folders += Get-Item -Path "C:\Windows\Tracing"

        # Gather trace files that generated in last 4 hours from defined folders 
        foreach ($folder in $folders){
            $logfiles = Get-ChildItem -Path $folder.FullName | Where-Object {$_.LastWriteTime -gt $using:FromDate -and $_.Attributes -ne "Directory"}
            foreach ($file in $logfiles){
                if(!(Test-Path -Path "$DataCollectionDir\$($folder.Name)" -PathType Container)){
                    New-Item -Path "$DataCollectionDir\$($folder.Name)" -ItemType Directory
                }
                if($file.LastWriteTime -gt $using:FromDateNc -and $file.Parent -ne "CrashDumps"){
                    Copy-Item $file.FullName -Destination "$DataCollectionDir\$($folder.Name)"
                }
            }
        }

        $EventLogs = @()
        $EventLogs += Get-WinEvent -ListLog Application
        $EventLogs += Get-WinEvent -ListLog System

        if($role -eq "NC")
        {
            # Collect Logs for network controller role
            New-Item -Path "$DataCollectionDir\ServiceFabric" -ItemType Directory | Out-Null
            $SFLogs = Get-ChildItem -Path "C:\ProgramData\Microsoft\Service Fabric\log\Traces" | Where-Object {$_.LastWriteTime -gt $using:FromDateSf}
            foreach($SFLog in $SFLogs)
            {
                Copy-Item $SFLog.FullName -Destination "$DataCollectionDir\ServiceFabric"
            }

            $EventLogs += Get-WinEvent -ListLog *NetworkController* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *ServiceFabric* | Where-Object {$_.RecordCount}      

            ### Get IMOS DB Info
            #Collect SF Cluster IMOS DB File info
            $sfClusterConnection = Connect-ServiceFabricCluster
            if($sfClusterConnection)
            {
                Write-Log "Collecting Network Controller IMOS Store Info"
                $ncServices = Get-ServiceFabricService -ApplicationName "fabric:/NetworkController"
                # service fabric base folder
                $svcFabricPath = "C:\ProgramData\Microsoft\Service Fabric\$(HostName)\Fabric\work\Applications\NetworkController_App0\work"
                $imosInfo = @()
                foreach($ncService in $ncServices)
                {
                    #Get partition ID
                    $partitionId = (Get-ServiceFabricPartition -ServiceName $ncService.ServiceName).PartitionId
                    $imosPath = Join-Path -Path $svcFabricPath -ChildPath "P_$partitionId"
                    #Get replica ID
                    $replicaId = (Get-ServiceFabricReplica -PartitionId $partitionId | Where-Object NodeName -EQ $(HostName)).ReplicaId
                    $path = Join-Path -Path $imosPath -ChildPath "R_$replicaId\ImosStore"
                    if(Test-Path $path)
                    {
                        #Write-Host "[$(HostName)] $($ncService.ServiceName) IMOS Size: $((Get-Item $path).length)"
                        $imosFile = Get-Item $path
                        $imosInfo += [PSCustomObject]@{
                        NC = $(HostName)
                        ServiceName = $ncService.ServiceName
                        ServicePartitionId = $partitionId
                        ImosSizeinKB = ($imosFile.length)/1KB
                        LastWriteTime = $imosFile.LastWriteTime
                        }
                    }
                    
                }
                $imosInfo | ft | Out-File -FilePath "$DataCollectionDir\IMOSDBInfo.txt"

                Write-Log "Collecting Network Controller Status"
                New-Item -Path "$DataCollectionDir\NetworkControllerStatus" -ItemType Directory | Out-Null
                $client = [System.Fabric.FabricClient]::new()
                $task = $client.PropertyManager.EnumeratePropertiesAsync("fabric:/NetworkController/GlobalConfiguration", $true, $null)
                $task.Result | ForEach-Object {$name=$_.Metadata.PropertyName; $value=[System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string]).Invoke($_, $null); "Name:"+$name +", "+ "Value:"+$value} >> "$DataCollectionDir\NetworkControllerStatus\GlobalConfiguration.txt"
    
                $NCUri = "fabric:/NetworkController"
                Get-ServiceFabricClusterManifest | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\ClusterManifest.xml"
                Get-ServiceFabricClusterHealth | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\ClusterHealth.txt"

                $NCApp = Get-ServiceFabricApplication -ApplicationName $NCUri 
                $NCApp | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCApp.txt"
                Get-ServiceFabricApplicationManifest -ApplicationTypeName $NCApp.ApplicationTypeName -ApplicationTypeVersion $NCApp.ApplicationTypeVersion | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCAppManifest.txt"
                Get-ServiceFabricApplicationHealth -ApplicationName $NCUri | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCAppHealth.txt"

                $NCServices = Get-ServiceFabricService -ApplicationName $NCUri
                $NCServices | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\NCServices.txt"
                foreach ($service in $NCServices){
                    $serviceTypeName=$service.ServiceTypeName
                    Get-ServiceFabricServiceHealth -ServiceName $service.ServiceName.AbsoluteUri | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"

                    $partition = Get-ServiceFabricPartition -ServiceName $service.ServiceName.AbsoluteUri 
                    $replicas = Get-ServiceFabricReplica -PartitionId $partition.PartitionId
                    $replicas | Out-File -FilePath "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt" 
                    foreach($replica in $replicas){
                        if($replica.ReplicaId){
                            Get-ServiceFabricReplicaHealth -PartitionId $partition.PartitionId -ReplicaOrInstanceId $replica.ReplicaId >> "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"
                        }
                        else {
                            Get-ServiceFabricReplicaHealth -PartitionId $partition.PartitionId -ReplicaOrInstanceId $replica.InstanceId >> "$using:DataCollectionDir\NetworkControllerStatus\$serviceTypeName.txt"
                        }
                    }
                }
                
            }else
            {
                Write-Log "Failed to connect to Service Fabric Cluster" -Type "Error"
            }
           

        }elseif($role -eq "MUX")
        {
            Write-Log "Collecting MUX Logs"
            # Collect Logs for MUX role
            $EventLogs += Get-WinEvent -ListLog *SLBMux* | Where-Object {$_.RecordCount}

            # MUX Driver Control Console Output
            MuxDriverControlConsole.exe /GetMuxState | Out-File "$DataCollectionDir\MuxState.txt"
            MuxDriverControlConsole.exe /GetMuxConfig | Out-File "$DataCollectionDir\MuxConfig.txt"
            MuxDriverControlConsole.exe /GetMuxStats | Out-File "$DataCollectionDir\MuxStats.txt"
            MuxDriverControlConsole.exe /GetMuxVipList | Out-File "$DataCollectionDir\MuxVipList.txt"
            MuxDriverControlConsole.exe /GetMuxDripList | Out-File "$DataCollectionDir\MuxDripList.txt"
            MuxDriverControlConsole.exe /GetStatelessVip | Out-File "$DataCollectionDir\StatelessVip.txt"
            MuxDriverControlConsole.exe /GetStatefulVip | Out-File "$DataCollectionDir\StatefulVip.txt"
        }
        elseif($role -eq "GW")
        {
            Write-Log "Collecting Gateway Logs"
            # Collect Logs for GW
            $EventLogs += Get-WinEvent -ListLog *RemoteAccess* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *VPN* | Where-Object {$_.RecordCount}
            $EventLogs += Get-WinEvent -ListLog *IKE* | Where-Object {$_.RecordCount}       
            
            Get-RemoteAccess | Out-File "$DataCollectionDir\Get-RemoteAccess.txt"
            Get-VpnServerConfiguration | Out-File "$DataCollectionDir\Get-VpnServerConfiguration.txt"
            Get-VpnS2SInterface | Format-List * | Out-File "$DataCollectionDir\Get-VpnS2SInterface.txt"
            Get-RemoteaccessRoutingDomain | Format-List * | Out-File "$DataCollectionDir\Get-RemoteAccessRoutingDomain.txt"  
            foreach ($routingDomain in Get-RemoteAccessRoutingDomain){
                New-Item -Path "$DataCollectionDir\$($routingDomain.RoutingDomainID)" -ItemType Directory | Out-Null
                Get-BgpRouter -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpRouter.txt"
                Get-BgpPeer -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpPeer.txt"
                Get-BgprouteInformation -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpRouteInformation.txt"
                Get-BgpCustomRoute -RoutingDomain $routingDomain.RoutingDomain | Format-List * | Out-File "$DataCollectionDir\$($routingDomain.RoutingDomainID)\Get-BgpCustomRoute.txt"
            } 
            Set-Content -Path "$DataCollectionDir\README.txt" -Value "ETL files to be decoded using InsightClient"
            # Ensure we cleanup RAS logs from tracing
            # Remove-Item -Path "C:\Windows\Tracing\*.log"
            # Remove-Item -Path "C:\Windows\Tracing\*.etl"
        }elseif($role -eq "HyperV")
        {
            Write-Log "Collecting Hyper-V Logs"
            $EventLogs += Get-WinEvent -ListLog *Hyper-V* | Where-Object {$_.RecordCount} 
             # Gather VFP port configuration details
            New-Item -Path "$DataCollectionDir\VFP" -ItemType Directory -Force | Out-Null
            $vmAdapters = Get-VMNetworkAdapter *
            $VMAdapterPortInfos = @()
            $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
            foreach($vmAdapter in $vmAdapters){
                Write-Host "Getting VM Adapter Port Info for $vmAdapter"
                $PortSettings = $vmAdapter | Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
                $portid = (Get-VMSwitchExtensionPortData -VMName $vmAdapter.VMName -VMNetworkAdapterName $vmAdapter.Name)[0].data.deviceid
                foreach($PortSetting in $PortSettings){
                    $VMAdapterPortInfo = [PSCustomObject]@{
                            VMName = $vmAdapter.VMName
                            VMAdapterName= $vmAdapter.Name
                            PortId = $portid
                            PortProfileId = $PortSetting.SettingData.ProfileId
                            PortProfileName = $PortSetting.SettingData.ProfileName
                        }
                        $VMAdapterPortInfos += $VMAdapterPortInfo
                }
            }

            $mgmtVmAdapters = Get-VMNetworkAdapter -ManagementOS
            foreach($mgmtVmAdapter in $mgmtVmAdapters)
            {
                Write-Host "Getting VM Adapter Port Info for $mgmtVmAdapter"
                $portid = (Get-VMSwitchExtensionPortData -ManagementOS -VMNetworkAdapterName $mgmtVmAdapter.Name)[0].data.deviceid
                $VMAdapterPortInfo = [PSCustomObject]@{
                    VMName = "ManagementOS"
                    VMAdapterName= $mgmtVmAdapter.Name
                    PortId = $portid
                    PortProfileId = $null
                    PortProfileName = $null
                }
                $VMAdapterPortInfos += $VMAdapterPortInfo
                
            } 
            
            $VMAdapterPortInfos | Out-File "$DataCollectionDir\VMNetworkAdapterPort.txt"

            foreach($vmAdapterPort in $VMAdapterPortInfos)
            {
            vfpctrl.exe /list-rule /port:$($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_RuleInfo.txt"
            vfpctrl.exe /list-nat-range /port $($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_NatInfo.txt"
            vfpctrl.exe /list-mapping /port $($vmAdapterPort.PortId) | Out-File "$DataCollectionDir\VFP\$($vmAdapterPort.VMName)_$($vmAdapterPort.PortId)_ListMapping.txt"
            }
             # Gather OVSDB databases
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Out-File "$DataCollectionDir\ovsdb_vtep.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Out-File "$DataCollectionDir\ovsdb_firewall.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ServiceInsertion | Out-File "$DataCollectionDir\ServiceInsertion.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep -f json -pretty| Out-File "$DataCollectionDir\ovsdb_vtep.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall -f json -pretty | Out-File "$DataCollectionDir\ovsdb_firewall.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ServiceInsertion | Out-File "$DataCollectionDir\ServiceInsertion.json"
            vfpctrl /list-vmswitch-port | Out-File "$DataCollectionDir\vfpctrl_list-vmswitch-port.txt"

            # Gather Hyper-V network details
            Get-PACAMapping | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-PACAMapping.txt"
            Get-ProviderAddress | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-ProviderAddress.txt"
            Get-CustomerRoute | Sort-Object PSComputerName | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-CustomerRoute.txt"
            Get-NetAdapterVPort | Out-File "$DataCollectionDir\Get-NetAdapterVPort.txt"
            Get-NetAdapterVmqQueue | Out-File "$DataCollectionDir\Get-NetAdapterVMQQueue.txt"
            Get-VMSwitch | Format-List * | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-VMSwitch.txt"
            Get-VMSwitchTeam | Format-List * | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-VMSwitchTeam.txt"

            # Gather registry key properties for nchostagent and other nc services
            $RegKeyDirectories = @()
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent -Recurse
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy
            $RegKeyDirectories += Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\DnsProxy -Recurse
            $RegKeyDirectories = $RegKeyDirectories | Sort-Object -Unique

            foreach($obj in $RegKeyDirectories){
                if($obj.PSPath -like "*NCHostAgent*"){
                    Get-ItemProperty -Path $obj.PSPath | Out-File -Encoding ascii "$DataCollectionDir\Registry_NCHostAgent.txt" -Append
                }
                if($obj.PSPath -like "*DnsProxy*"){
                    Get-ItemProperty -Path $obj.PSPath | Out-File -Encoding ascii "$DataCollectionDir\Registry_DnsProxy.txt" -Append
                }
            }

            # [RS5] Gather nvspinfo.exe results
            if([System.Environment]::OSVersion.Version.Build -eq '17763'){
                nvspinfo.exe -e | Out-File -FilePath "$DataCollectionDir\NVSPInfo.txt"
            }
        }

        Write-Log "Procesing Event Logs"
        $EventLogFolder = "$DataCollectionDir\EventLogs"
        if(!(Test-Path -Path $EventLogFolder -PathType Container)){
            New-Item -Path $EventLogFolder -ItemType Directory -Force | Out-Null
        }
        foreach ($EventLog in $EventLogs){
            #Get-WinEvent -LogName $EventLog.LogName | Where-Object {$_.TimeCreated -gt $using:FromDate} | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message | Export-Csv -Path "$EventLogFolder\$($EventLog.LogName).csv".Replace("/","_") -NoTypeInformation
            wevtutil epl $EventLog.LogName "$EventLogFolder\$($EventLog.LogName).evtx".Replace("/","_")
        }        
    
        # Gather general configuration details from all nodes
        Get-ComputerInfo | Out-File "$DataCollectionDir\Get-ComputerInfo.txt"
        Get-Hotfix | Out-File "$DataCollectionDir\Get-Hotfix.txt"
        Get-NetAdapter | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetAdapter.txt"
        foreach($NetAdapter in Get-NetAdapter){
            Get-NetAdapter -Name $NetAdapter.Name | Format-List * | Out-File "$DataCollectionDir\Get-NetAdapter_$($NetAdapter.Name).txt"
            Get-NetAdapterAdvancedProperty -Name $NetAdapter.Name | Format-List * | Out-File "$DataCollectionDir\Get-NetAdapterAdvancedProperty_$($NetAdapter.Name).txt"    
        }
        
        Get-Service | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-Service.txt"
        Get-Process | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-Process.txt"
        ipconfig /allcompartments /all | Out-File "$DataCollectionDir\ipconfig_allcompartments.txt"
        Get-NetIPInterface | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetIPInterface.txt"
        Get-NetNeighbor | Format-Table -AutoSize | Out-String -Width 4096 | Out-File "$DataCollectionDir\Get-NetNeighbor.txt"
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Out-File "$DataCollectionDir\Get-NetRoute.txt"
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-Csv -Path "$DataCollectionDir\Get-NetTCPConnection.csv" -NoTypeInformation

        Write-Log "Collecting Certificates Information"
        # Gather certificates from all nodes
        $CertLocationPaths = @(
        'Cert:\LocalMachine\My'
        'Cert:\LocalMachine\Root'
        )
        foreach ($CertLocation in $CertLocationPaths){
            $Certificates = @()
            $CertificateList = Get-ChildItem -Path $CertLocation -Recurse | Where-Object {$_.PSISContainer -eq $false}
            foreach($cert in $CertificateList){
                $obj = New-Object -TypeName psobject
                $obj | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $cert.FriendlyName
                $obj | Add-Member -MemberType NoteProperty -Name "Subject" -Value $cert.Subject
                $obj | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $cert.Issuer
                $obj | Add-Member -MemberType NoteProperty -Name "Thumbprint" -Value $cert.Thumbprint
                $obj | Add-Member -MemberType NoteProperty -Name "HasPrivateKey" -Value $cert.HasPrivateKey
                $obj | Add-Member -MemberType NoteProperty -Name "PrivateKey" -Value $cert.PrivateKey
                $obj | Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $cert.NotBefore
                $obj | Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $cert.NotAfter
                $obj | Add-Member -MemberType NoteProperty -Name "Archived" -Value $cert.Archived
                $obj | Add-Member -MemberType NoteProperty -Name "DnsNameList" -Value $cert.DnsNameList
                $obj | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $cert.SerialNumber
                $obj | Add-Member -MemberType NoteProperty -Name "EnhancedKeyUsageList" -Value $cert.EnhancedKeyUsageList
                if($cert.PrivateKey){
                    $acl = Get-Acl -Path ("$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\" + $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)
                    $obj | Add-Member -MemberType NoteProperty -Name "AccesstoString" -Value $acl.AccessToString
                    $obj | Add-Member -MemberType NoteProperty -Name "Sddl" -Value $acl.Sddl
                }
                $Certificates += $obj
            }
            $DirFriendlyName = $CertLocation.Replace(":","").Replace("\","_")
            $Certificates | Export-Csv -NoTypeInformation "$DataCollectionDir\$DirFriendlyName.csv"
        }

        Write-Log "Collecting NetSetup Logs"
        # Gather files related to network setup from all nodes
        $NetSetupFiles = @(
            "$env:SystemRoot\Panther\setupact.log"
            "$env:SystemRoot\INF\setupapi.*"
            "$env:SystemRoot\logs\NetSetup\*"
        )

        New-Item "$DataCollectionDir\NetSetupLogs" -ItemType Directory | Out-Null
        foreach($file in $NetSetupFiles){
            Copy-Item -Path $file -Destination "$DataCollectionDir\NetSetupLogs"
        }

        Write-Log "Data Collection Completed"
    } -ArgumentList $Role,$DataCollectionDir
    # -AsJob -JobName ($Id = "$([guid]::NewGuid())")

    # Monitor the job status
    #Get-JobStatus -JobName $Id -ExecutionTimeOut 300 -PollingInterval 1

    # Copy the logs
    foreach($InfraNode in $InfraNodes)
    {
        Write-Log "Copying logs from $InfraNode to $OutputPath"
        $RemotePathToCopy = "\\$InfraNode\c$\Temp\CSS_SDN\*"
        New-Item -Path "$OutputPath\$InfraNode" -ItemType Directory -Force | Out-Null
        Copy-Item -Path $RemotePathToCopy -Destination "$OutputPath\$InfraNode" -Recurse | Out-null
    }

}
Function Get-SDNHostLogs([String[]]$SDNHosts,  [String]$OutputPath){

    if($SDNHosts.Count -gt 0){
        Invoke-Command -ComputerName $SDNHosts -ScriptBlock{
            New-item -Path c:\SDNHostTrace -ItemType Directory -Force
            Get-VM | ft -AutoSize > c:\SDNHostTrace\Get-VM.txt
            Get-VMNetworkAdapter *| ft -AutoSize > c:\SDNHostTrace\Get-VMNetworkAdapter.txt
            Get-VMNetworkAdapter -ManagementOS | ft -AutoSize > c:\SDNHostTrace\Get-VMNetworkAdapterMgmt.txt
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep > c:\SDNHostTrace\ovsdb.txt
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Out-File "c:\SDNHostTrace\ovsdb_vtep.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Out-File "c:\SDNHostTrace\\ovsdb_firewall.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ServiceInsertion | Out-File "c:\SDNHostTrace\ServiceInsertion.txt"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep -f json -pretty| Out-File "c:\SDNHostTrace\ovsdb_vtep.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall -f json -pretty | Out-File "c:\SDNHostTrace\ovsdb_firewall.json"
            ovsdb-client.exe dump tcp:127.0.0.1:6641 ServiceInsertion | Out-File "c:\SDNHostTrace\ServiceInsertion.json"
            Get-ProviderAddress > c:\SDNHostTrace\Get-ProviderAddress.txt
            Get-PACAMapping > c:\SDNHostTrace\Get-PACAMapping.txt
            Get-VMSwitch | fl * > c:\SDNHostTrace\Get-VMSwitch.txt
            ipconfig /allcompartments /all > c:\SDNHostTrace\ipconfig_all.txt

            Tasklist /svc > C:\SDNHostTrace\tasklist.txt
            New-Item -Path C:\SDNHostTrace\EventLogs -ItemType Directory -Force
            copy c:\Windows\System32\winevt\Logs\System.evtx c:\SDNHostTrace\EventLogs
            copy c:\Windows\System32\winevt\Logs\Application.evtx c:\SDNHostTrace\EventLogs
            Get-ChildItem HKLM:System\CurrentControlSet\Services\NcHostAgent -Recurse > c:\SDNHostTrace\NcHostAgentReg.txt
            Get-ChildItem cert:\localmachine\root | %{ 
                if($_.Subject -ne $_.Issuer){
                    "CA Issued Cert Found at Root Store : $($_.Thumbprint),$($_.Subject)" >> c:\SDNHostTrace\RootCerts.txt
                }
            }


            Write-Host -ForegroundColor Green "Getting VM Network Adapter Port Info..."
            $vmAdapters = Get-VMNetworkAdapter *
            $VMAdapterPortInfos = @()
            $PortProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
            foreach($vmAdapter in $vmAdapters){
                Write-Host "Getting VM Adapter Port Info for $vmAdapter"
                $PortSettings = $vmAdapter | Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId
                $portid = (Get-VMSwitchExtensionPortData -VMName $vmAdapter.VMName -VMNetworkAdapterName $vmAdapter.Name)[0].data.deviceid
                foreach($PortSetting in $PortSettings){
                    $VMAdapterPortInfo = [PSCustomObject]@{
                            VMName = $vmAdapter.VMName
                            VMAdapterName= $vmAdapter.Name
                            PortId = $portid
                            PortProfileId = $PortSetting.SettingData.ProfileId
                            PortProfileName = $PortSetting.SettingData.ProfileName
                        }
                        $VMAdapterPortInfos += $VMAdapterPortInfo
                }
            }

            $mgmtVmAdapters = Get-VMNetworkAdapter -ManagementOS
            foreach($mgmtVmAdapter in $mgmtVmAdapters)
            {
                Write-Host "Getting VM Adapter Port Info for $mgmtVmAdapter"
                $portid = (Get-VMSwitchExtensionPortData -ManagementOS -VMNetworkAdapterName $mgmtVmAdapter.Name)[0].data.deviceid
                $VMAdapterPortInfo = [PSCustomObject]@{
                    VMName = "ManagementOS"
                    VMAdapterName= $mgmtVmAdapter.Name
                    PortId = $portid
                    PortProfileId = $null
                    PortProfileName = $null
                }
                $VMAdapterPortInfos += $VMAdapterPortInfo
                
            } 
            
            $VMAdapterPortInfos | ft * > c:\SDNHostTrace\VMNetworkAdapterPort.txt

            New-Item -Path C:\SDNHostTrace\VFPRules -ItemType Directory -Force
            foreach($vmAdapterPort in $VMAdapterPortInfos)
            {
                vfpctrl.exe /port:$($vmAdapterPort.PortId) /list-rule > C:\SDNHostTrace\VFPRules\$($vmAdapterPort.PortId).txt
            }

            #netstat info to check connection state to 6640
            netstat -anob > c:\SDNHostTrace\netstat.txt
        } 

        Write-Host "Copying logs from SDN Hosts"
        foreach($SDNHost in $SDNHosts)
        {
            Write-Host "Copying logs from $SDNHost to $OutputPath"
            $RemotePathToCopy = "\\$SDNHost\c$\SDNHostTrace"
            New-Item -Path "$OutputPath\$SDNHost" -ItemType Directory -Force
            Copy-Item -Path $RemotePathToCopy -Destination "$OutputPath\$SDNHost" -Recurse
        }
    }else
    {
        Write-Error "No SDN Hosts Specified"
        return
    }
}

Function Get-OutputPath([String]$OutputPath)
{
    if([String]::IsNullOrEmpty($OutputPath))
    {
        $OutputPath = Get-Date -Format "yyyyMMddHHmmss"
        Write-Host "Creating log path $OutputPath"
        New-Item $OutputPath -ItemType Directory -Force | Out-Null
    }
    return $OutputPath
}

Function Clean-SDNHostLogs([String[]]$SDNHosts)
{
    Invoke-Command -ComputerName $SDNHosts -ScriptBlock{
        Param(
            [bool]$IncludeVfp
        )
        Write-Host "[$(HostName)]Cleanning up c:\SDNHostTrace"
        $HostLogPath = "C:\SDNHostTrace"
        if(Test-Path $HostLogPath){
            Write-Host "[$(HostName)]Log path $HostLogPath existed, remove the old logs and recreate"
            Remove-Item -Path $HostLogPath -Recurse -Force
        }
        New-Item -Path $HostLogPath -ItemType Directory -Force
        Write-Host "[$(HostName)]Log path $HostLogPath created and cleaned up"
    }
}

Function Get-RequiredModules()
{
    $feature = get-windowsfeature "RSAT-NetworkController"
    if (!$feature.Installed) {
        Write-Log "RSAT-NetworkController Not Installed"
        add-windowsfeature "RSAT-NetworkController" -Confirm
        $feature = get-windowsfeature "RSAT-NetworkController" 
    }else
    {
        Write-Log "RSAT-NetworkController Installed"
    }
    return $feature.Installed
}


Function Get-SdnVirtualServerAddress(
    [String] $NcUri,
    [String] $ResourceId
)
{
    #Write-Log "Getting Virtual Server from $NcUri with resource Id: $ResourceId"
    $virtualServerResource = Get-NetworkControllerVirtualServer -ConnectionUri $NcUri -ResourceId $ResourceId
    
    if($virtualServerResource -ne $null)
    {
        #Write-Log "Looking for Virtual Server Connections"
        if($virtualServerResource.properties.connections -ne $null)
        {
            #Write-Log "Looking for Virtual Server Connection Management Address"
            if($virtualServerResource.properties.connections[0].managementaddresses -ne $null)
            {
                return $virtualServerResource.properties.connections[0].managementaddresses[0]
            }
        }
    }

    #Write-Log "No Virtual Server resource found"
    return ""
}
Function Get-SdnInfraVMs(
    [String] $NCVMName,
    [String] $NcUri
)
{
    Write-Log "Getting SDN Infra VMs from $NcUri"
    Write-Log "Looking for SDN NC"
    $global:NcVMs = (Get-NetworkControllerNode -ComputerName $NCVMName).Server

    Write-Log "Looking for SDN MUX"
    $muxResources = Get-NetworkControllerLoadBalancerMux -ConnectionUri $NcUri
    foreach($muxResource in $muxResources)
    {
        $muxVirtualServerResourceId = $muxResource.properties.virtualserver.ResourceRef -replace "/VirtualServers/"
        $muxVirtualServerAddress = Get-SdnVirtualServerAddress -ResourceId $muxVirtualServerResourceId -NcUri $NcUri
        if($muxVirtualServerAddress -eq $null)
        {
            Write-Log "MUX $($muxResources.ResourceId) pointed to virtual server $muxVirtualServerResourceId have no management address found" -Type "Warning"
        }else
        {
            $global:MuxVMs += $muxVirtualServerAddress
        }
    }

    Write-Log "Looking for SDN Gateway"
    $gwResources = Get-NetworkControllerGateway -ConnectionUri $NcUri
    foreach($gwResource in $gwResources)
    {
        $gwVirtualServerResourceId = $gwResource.properties.virtualserver.ResourceRef -replace "/VirtualServers/"
        $gwVirtualServerAddress = Get-SdnVirtualServerAddress -ResourceId $gwVirtualServerResourceId -NcUri $NcUri
        if($gwVirtualServerAddress -eq $null)
        {
            Write-Log "Gateway $($muxResources.ResourceId) pointed to virtual server $gwVirtualServerResourceId have no management address found" -Type "Warning"
        }else
        {
            $global:GwVMs += $gwVirtualServerAddress
        }
    }
}

$ScriptVersion = "2020.2.24"
$GetSDNHostTraceNow = $true;
$global:OutputPath = ""
# The Temp DataCollection Dir on Infra Servers
$global:DataCollectionDir = "C:\Temp\CSS_SDN"
$global:NcUri = ""

#Infra VMs
$global:NcVMs = @()
$global:GwVMs = @()
$global:MuxVMs = @()


if($StartSDNHostTrace)
{
    Clean-SDNHostLogs -SDNHosts $SDNHosts
    Start-SDNHostLogs -SDNHosts $SDNHosts -IncludeVfp $IncludeVfp
    $GetSDNHostTraceNow = $false
}

if($StopSDNHostTrace)
{
    Stop-SDNHostLogs -SDNHosts $SDNHosts -IncludeVfp $IncludeVfp
    $GetSDNHostTraceNow = $true
}


if($GetSDNHostTraceNow -and $SDNHosts.Count -gt 0)
{
    $OutputPath = Get-OutputPath -OutputPath $OutputPath
    Write-Host $OutputPath
    if(!$StopSDNHostTrace)
    {
        #if this is called during stop SDN Host trace, the cleanup already done before
        Clean-SDNHostLogs -SDNHosts $SDNHosts
    }
    Get-SDNHostLogs -SDNHosts $SDNHosts -OutputPath $OutputPath
}

if([String]::IsNullOrEmpty($NCVMName))
{
    Write-Host "Trying to find RESTNAME automatically"
    if ( Test-Path "HKLM:\System\CurrentControlSet\Services\NcHostAgent" )
    {
        Write-Host "Getting RESTNAME from NCHOSTAGENT Registry"
        $registry = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NcHostAgent\Parameters"
        if ( $regsitry.Connections )
        {
            $RestName=$registry.Connections[0].Split(":")[1]
        }
        else
        {
            #Trying with Cert CNAME
            $RestName=$registry.PeerCertificateCName
        }
    }
    # Getting one NC Name from DNS
    $RestIP=(Resolve-DnsName $RestName).IpAddress
    $NCVMName=(Resolve-DnsName $RestIP).Namehost
}
else
{
    $RestName=$($nc.RestName)
}

if( $RestName -and $NCVMName)
{
    $nc = Get-NetworkController -ComputerName $NCVMName

    Write-Host "Collecting Network Controller traces"
    $OutputPath = Get-OutputPath -OutputPath $OutputPath
    Write-Log "SDNLogCollect Version: $ScriptVersion"
    Write-Log "TimeZone: $(Get-TimeZone)"

    $RequiredModuleInstalled = Get-RequiredModules

    if(!$RequiredModuleInstalled)
    {
        Write-Log "Required Module RSAT-NetworkController not installed" -Type Error
        return 
    }

    $NcUri = "https://$RestName"
    Write-Log "Retrieved the NcUri: $NcUri"

    Get-SdnInfraVMs -NCVMName $NCVMName -NcUri $NcUri
    Write-Log "NC: $NcVMs"
    Write-Log "MUX: $MuxVMs"
    Write-Log "Gateway: $GwVMs"

    Get-SdnInfraNodeLogs -InfraNodes $NcVMs -Role "NC" -OutputFolder $OutputPath
    Get-SdnInfraNodeLogs -InfraNodes $MuxVMs -Role "MUX" -OutputFolder $OutputPath
    Get-SdnInfraNodeLogs -InfraNodes $GwVMs -Role "GW" -OutputFolder $OutputPath
    
    Get-NCImosDump -NCVMName $NCVMName -OutputPath $OutputPath
    Get-SdnResources -NCVMName $NCVMName -OutputFolder $OutputPath -NcUri $NcUri
    Get-NCClusterInfo -NCVMName $NCVMName -OutputPath $OutputPath
}
