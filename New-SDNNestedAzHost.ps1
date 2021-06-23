Param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = ".\configfiles\SDNNestedAzHost.psd1",
    [String] $VMName = $null

)

Import-Module -Name Az.Compute
Import-Module -Name .\utils\SDNNested-Module.psm1

$res = get-module "Az.*" -ErrorAction SilentlyContinue
if ( ! $res )
{
    Write-SDNNestedLog "Az Powershell Modules are missing, installation is on going !"    
    Install-Module -Name Az -AllowClobber -Scope AllUsers -Force -confirm:$false
    Write-SDNNestedLog "ReRun the script !!!!" 
    sleep 10   
    exit 0
}

$Connected = Get-AzSubscription -ErrorAction Continue -OutVariable null 
if ( $Connected ) {
    "Already connected to the subscription"
}
else {
    Connect-AzAccount
}

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

#DNS ForbiddendChar
$ForbiddenChar = @("-", "_", "\", "/", "@", "<", ">", "#" , "&")

# Checking VM Name 
if( $null -eq $VMName ){ $VMName = $configdata.VMName }
if( ! $VMName )
{ 
    Write-SDNNestedLog "Please provide a VMName either from inline parameters or using ConfigFile"
    throw "Please provide a VMName either from inline parameters or using ConfigFile"
}

# Credentials for Local Admin account you created in the sysprepped (generalized) vhd image
if( ! $configdata.VMLocalAdminUser )
{
    $Credential = Get-Credential -Message "Please provide the AzureVM credential"
}
else
{
    $VMLocalAdminUser = $configdata.VMLocalAdminUser
    $VMLocalAdminSecurePassword = ConvertTo-SecureString $configdata.VMLocalAdminSecurePassword -AsPlainText -Force 
    $Credential = New-Object System.Management.Automation.PSCredential ($VMLocalAdminUser, $VMLocalAdminSecurePassword) 
}

# Checking ResourceGroupName is existing and getting the Az locaiton from it
$ResourceGroupName = $configdata.ResourceGroupName
$AzResourceGroupName = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ( ! ( $AzResourceGroupName ) )
{
    $list = Get-AzResourceGroup | select-object ResourceGroupName,Location
    Write-SDNNestedLog "See existing resource group"
    $list | ft
    throw "$ResourceGroupName does not exist on your subscription. Please create it First."
}
else
{
    $LocationName = $AzResourceGroupName.Location
}


# Checking that VMSize is available
$AzVMSize = Get-AzVMSize -Location $LocationName | ? Name -eq $configdata.VMSize 
if ( ! $AzVMSize )
{
    Write-SDNNestedLog "Please see current VMsize available in $LocationName"
    Write-Host -ForegroundColor Green "See https://azure.microsoft.com/en-us/blog/nested-virtualization-in-azure/"
    Write-SDNNestedLog "Please use one of the following VMSize"

    Get-AzVMSize -Location $LocationName | ? Name -match "_D.*_v3|_E.*_v3"

    throw "$($configdata.VMSize) does not exist in location $LocationName"
}
$VMSize = $AzVMSize.Name

#$SecurityGroupName = "$($VMName)_NetSecurityGroup"
#$subscription = $configdata.subscription

# Checking VNET
$VnetName = $configdata.VnetName
$SubnetName = $configdata.SubnetName
$storageType = $configdata.storageType
$VnetAddressPrefix = $configdata.VnetAddressPrefix
$SubnetAddressPrefix = $configdata.SubnetAddressPrefix

$AzVirtualNetwork = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ( ! $AzVirtualNetwork ) 
{
    Write-SDNNestedLog  "No VNET $VnetName found in $ResourceGroupName so going to create one"
   
    $AzVNetSubnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetAddressPrefix

    $AzVirtualNetwork = New-AzVirtualNetwork -Name $VnetName -ResourceGroupName $ResourceGroupName -Location $LocationName `
        -AddressPrefix $VnetAddressPrefix -Subnet $AzVNetSubnet
}
else
{
    $AzVNetSubnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $AzVirtualNetwork -Name $SubnetName -ErrorAction SilentlyContinue
    if ( ! $AzVNetSubnet )
    {
        Write-SDNNestedLog  "$SubnetName does not exist int $VnetName - please ResourceGroupName and VNet consistency"
        throw "$SubnetName does not exist int $VnetName - please ResourceGroupName and VNet consistency"
    }
}

$AzVNetSubnet = $AzVirtualNetwork.Subnets[0]

Write-SDNNestedLog  "$VMName will be connect to $VnetName / subnet $SubnetName"
# Checking Network Security Group
$NSGName = $configdata.NSGName

$AzNetworkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceName $NSGName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if ( ! $AzNetworkSecurityGroup )
{
    Write-SDNNestedLog "$NSGName does not exist so creation one called $NSGName."
    $AzNetworkSecurityGroup = New-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $ResourceGroupName `
                                -Location $LocationName
}

#Checking Network security rules
## Adding RCP + WMI
if ( !( $AzNetworkSecurityGroup.SecurityRules | ? destinationPortRange -eq "3389")  ) 
{
    $AzNetworkSecurityGroup | Add-AzNetworkSecurityRuleConfig -Name "Rdp-Rule" -Description "Allow WinRM" -Access "Allow" `
        -Protocol "Tcp" -Direction "Inbound" -Priority 100 -SourceAddressPrefix "Internet" -SourcePortRange "*" `
        -DestinationAddressPrefix "*" -DestinationPortRange "3389" | Set-AzNetworkSecurityGroup | Out-Null 
}

if ( !( $AzNetworkSecurityGroup.SecurityRules | ? destinationPortRange -eq "5985-5986")  ) 
{
    $AzNetworkSecurityGroup | Add-AzNetworkSecurityRuleConfig -Name "WinRM-Rule" -Description "Allow WinRM" -Access "Allow" `
        -Protocol "Tcp" -Direction "Inbound" -Priority 150 -SourceAddressPrefix "Internet" -SourcePortRange "*" `
        -DestinationAddressPrefix "*" -DestinationPortRange "5985-5986" | Set-AzNetworkSecurityGroup | Out-Null
}

#Public IP address and FQDN
$PublicIPAddressName = "$($VMName)_PIP1"
$DNSNameLabel = $VMName
foreach ($c in $ForbiddenChar) { $DNSNameLabel = $DNSNameLabel.ToLower().replace($c, "") }

Write-SDNNestedLog  "Creating Public Ip Address $PublicIPAddressName"
$AzPublicIpAddress = New-AzPublicIpAddress -Name $PublicIPAddressName -DomainNameLabel $DNSNameLabel `
    -ResourceGroupName $ResourceGroupName -Location $LocationName -AllocationMethod Dynamic -Force

if ( ! $AzPublicIpAddress )
{
    throw "Creating Public Ip Address $PublicIPAddressName success : $($AzPublicIpAddress.IpAddress)"
}

#VM NIC 
$NICName = "$($VMName)_NIC1"
$AzNetworkInterface = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName -Location $LocationName `
    -SubnetId $AzVNetSubnet.Id -PublicIpAddressId $AzPublicIpAddress.Id `
    -NetworkSecurityGroupId $AzNetworkSecurityGroup.Id -Force

if ( ! $AzNetworkInterface )
{ 
    throw "Failed to create $NICName"
}

$AzVM = New-AzVMConfig -VMName $VMName -VMSize $VMSize
$AzVM = Set-AzVMOperatingSystem -VM $AzVM -Windows -ComputerName $VMName -Credential $Credential -ProvisionVMAgent `
    -EnableAutoUpdate
$AzVM = Set-AzVMSourceImage -VM $AzVM -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2019-Datacenter' `
    -Version latest    
$AzVM = Add-AzVMNetworkInterface -VM $AzVM -Id $AzNetworkInterface.Id
$AzVM = Set-AzVMOSDisk -StorageAccountType $storageType -VM $AzVM -CreateOption "FromImage"

Write-SDNNestedLog  "Creating the AZ VM $VMName"

# Creating VM
$res = New-AzVm -ResourceGroupName $ResourceGroupName -Location $LocationName -VM $AzVM -LicenseType "Windows_Server" -Verbose    
$res
if ( ! $reS.IsSuccessStatusCode )
{
    Write-SDNNestedLog  "Creating the AZ VM $VMName failed !"
}
else
{
    Write-SDNNestedLog  "AZ VM $VMName successfully created"

    #Auto shutdown to save money
    $TimeZone = (Get-TimeZone).StandardName
    Write-SDNNestedLog  "Creating daily 8pm $TimeZone Auto shutdow for $VMName "
    Enable-AzRmVMAutoShutdown -ResourceGroupName $ResourceGroupName -VirtualMachineName $VMName -ShutdownTime 2000 -timezone $TimeZone

    $AzVM = get-AzVm -VMName $VMName
    $AzVM | Stop-AzVM -Force
    Write-SDNNestedLog  "AZ VM $VMName successfully stopped to add VMDataDisk $storageType"
    
    $AzDiskConfig = New-AzDiskConfig -Location $LocationName -DiskSizeGB $configdata.DiskSizeGB -AccountType $storageType `
        -CreateOption Empty 
    for ($i = 0; $i -lt $configdata.DiskNumber; $i++) 
    {
        $AzDisk = New-AzDisk -ResourceGroupName $ResourceGroupName -Disk $AzDiskConfig -DiskName "$($VMName)_DataDisk$i"
        $AzVM = Add-AzVMDataDisk -Name "$($VMName)_DataDisk$i" -Caching 'ReadWrite' -Lun $i -ManagedDiskId $AzDisk.Id `
            -CreateOption Attach -VM $AzVM
        Write-SDNNestedLog  "AZ VM $VMName Disk $i successfully added"    
    }

    Update-AzVM -ResourceGroupName $ResourceGroupName -VM $AzVM

    Write-SDNNestedLog  "AZ VM $VMName successfully updated"

    $AzVM | Start-AzVM
    Write-SDNNestedLog  "Starting AZ VM $VMName / $($AzPublicIpAddress.DnsSettings.Fqdn)"

    #while ( ! ( (tnc sdn01202019.francecentral.cloudapp.azure.com -p 3389).TcpTestSucceeded ) ){ sleep 1 }

    New-Item -ItemType File -Path $env:temp\injectedscript.ps1  | Out-Null

    $Content = "winrm qc /force
netsh advfirewall firewall add rule name=WinRMHTTP dir=in action=allow protocol=TCP localport=5985
netsh advfirewall firewall add rule name=WinRMHTTPS dir=in action=allow protocol=TCP localport=5986
"

    Add-Content $env:temp\injectedscript.ps1 $Content  | Out-Null
    
    Write-SDNNestedLog  "AZ VM $VMName  Adding WinRM Firewall rules"
    Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -ScriptPath $env:temp\injectedscript.ps1 `
        -CommandId 'RunPowerShellScript' | Out-Null
    Remove-Item $env:temp\injectedscript.ps1

    winrm set winrm/config/client '@{TrustedHosts="*"}' | Out-Null
    
    #Wait till VM is not READY
    Write-SDNNestedLog "$VMName is booting"
    while ((Invoke-Command $AzPublicIpAddress.DnsSettings.Fqdn -Credential $Credential { $env:COMPUTERNAME } `
            -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }  
    Write-SDNNestedLog "$VMName is Online"

    #Creating Virtual Disk from VM's AzDisk attached and format partition 
    #https://docs.microsoft.com/fr-fr/windows-server/storage/storage-spaces/deploy-standalone-storage-spaces
    Invoke-Command $AzPublicIpAddress.DnsSettings.Fqdn -Credential $Credential {
        $configdata = $args[0]

        $VMName = $env:COMPUTERNAME
        
        $VDiskResiliency = "Simple"
        $disks = Get-physicaldisk | where canpool -eq $true
        $StoragePool = Get-StorageSubsystem | New-StoragePool -Friendlyname MyPool -PhysicalDisks $disks

        $virtualDisk = new-VirtualDisk -StoragePoolFriendlyName $StoragePool.FriendlyName -FriendlyName "VirtualDisk1" `
                        -ResiliencySettingName $VDiskResiliency -UseMaximumSize -NumberOfColumns $disks.Count

        if ( ! $virtualDisk)
        {
            Write-Host "$VMName : creating virtual Disk failed"
            throw "$VMName : creating virtual Disk failed"
        }
        Write-Host "$VMName : virtual Disk succesfully created"

        $DriveLetter = $configdata.vDiskDriveLetter
        $DriveLetternnocolon = $DriveLetter.replace(":","")

        $Partition = Get-VirtualDisk -FriendlyName $virtualDisk.FriendlyName | Get-Disk | Initialize-Disk -PassThru | `
                        New-Partition -DriveLetter $DriveLetternnocolon -UseMaximumSize 
        
        if ( ! $partition )
        {
            Write-Host "$VMName : creating partition failed"
            throw "$VMName : creating partition failed"
        }
        Write-Host "$VMName : partition $DriveLetter succesfully created"
        
        $res = $partition | Format-Volume
        if ( ! $res )
        {
            Write-Host "$VMName : format operation failed on partition $DriveLetter"
            throw "$VMName : creating partition failed"
        }

        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*.sdn.lab" -Force

        Write-Host "$VMName : Add WinDefender exclusion for VHD/VHDX files"
        Add-MpPreference -ExclusionExtension "vhd"
        Add-MpPreference -ExclusionExtension "vhdx"
 
        Write-Host "$VMName : Creating folder for VMs Storage"

        if (! (Test-Path "$($DriveLetter)\VMs") ) { 
            New-Item -ItemType Directory "$($DriveLetter)\VMs" | Out-Null
            New-Item -ItemType Directory "$($DriveLetter)\VMs\Template" | Out-Null
        }
        if (! (Test-Path "$($DriveLetter)\VMs\Template") ) { 
            New-Item -ItemType Directory "$($DriveLetter)\VMs\Template" | Out-Null
        }

        
        if ( $configdata.AzFileShare )
        {
            Write-Host "$VMName : Mapping FileShare to get VHDX templates"
            $AzFileShare = $configdata.AzFileShare
            #$AzFQDN = ($AzFileShare).replace("\\", "").split("\")[0]
            $AZFileUser = $configdata.AZFileUser    
            $AZFilePwd = $configdata.AZFilePwd

            $AZFileSecurePassword = ConvertTo-SecureString $AZFilePwd -AsPlainText -Force 
            $Credential = New-Object System.Management.Automation.PSCredential ($AZFileUser, $AZFileSecurePassword) 
            #cmdkey /add:$AzFQDN /user:$AZFileUser /pass:$AZFilePwd
            #net use Z: $AzFileShare /user:$AZFileUser $AZFilePwd /persistent:yes
            New-SmbGlobalMapping -LocalPath Z: -RemotePath $AzFileShare -Credential $Credential -Persistent $true

            Write-Host "$VMName : Copying files, it could take a while"

            if ( Test-Path $DriveLetter) 
            {
                #cp Z:\Template\*.vhdx "$($DriveLetter)\VMs\Template" 
                Robocopy.exe Z:\Template "$($DriveLetter)\VMs\Template" /MT /np
                Robocopy.exe Z:\apps "$($DriveLetter)\apps"  /MT /np
            }
        }
        else
        {
            Write-Host "$VMName : THINK to copy VHDX Template to $DriveLetter" 
        }
        Write-Host "$VMName : Installing HYPV feature" 
        Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
    
        #Set-VMHost -EnableEnhancedSessionMode $true
    } -ArgumentList $configdata

    #Wait till VM is not READY
    Write-SDNNestedLog "$VMName is booting"

    while ((Invoke-Command $AzPublicIpAddress.DnsSettings.Fqdn -Credential $Credential { $env:COMPUTERNAME } `
        -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }  
    
    Write-SDNNestedLog "AZ VM $VMName is running and can be RDP to $($AzPublicIpAddress.DnsSettings.Fqdn)"
    Write-SDNNestedLog "mstsc /v:$($AzPublicIpAddress.DnsSettings.Fqdn)"

    Write-SDNNestedLog  `
        "You are ready to deploy SDN Stack. Before running the SDNNEsted.ps1 script please ensure to have VHD template uploaded to the AzureVM"
}