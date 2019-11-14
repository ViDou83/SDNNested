Param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = ".\configfiles\AzureVM.psd1"
)

Import-Module -Name Az.Compute

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
    Write-Host "Using configuration file passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
}
elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
    Write-Host "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
    Write-Host "Configuration file $ConfigurationDataFile version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express."
    Write-Host "Please update your config file to match the version $scriptversion example."
    return
}

$ForbiddenChar = @("-", "_", "\", "/", "@", "<", ">", "#")

# Credentials for Local Admin account you created in the sysprepped (generalized) vhd image
$VMLocalAdminUser = $configdata.VMLocalAdminUser
$VMLocalAdminSecurePassword = ConvertTo-SecureString $configdata.VMLocalAdminSecurePassword -AsPlainText -Force 

## Azure Account
$VMSize = $configdata.VMSize
$LocationName = $configdata.LocationName
$ResourceGroupName = $configdata.ResourceGroupName
$VnetName = $configdata.VnetName
$SubnetName = $configdata.SubnetName
$VMName = $configdata.VMName
$SecurityGroupName = "$($VMName)_NetSecurityGroup"
$PublicIPAddressName = "$($VMName)_PIP1"
$subscription = $configdata.subscription
$NICName = "$($VMName)_NIC1"
$DNSNameLabel = $VMName
$storageType = $configdata.storageType

$NSGName = $configdata.NSGName

foreach ($c in $ForbiddenChar) { $DNSNameLabel = $DNSNameLabel.ToLower().replace($c, "") }

$Credential = New-Object System.Management.Automation.PSCredential ($VMLocalAdminUser, $VMLocalAdminSecurePassword) 

$VNET = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $ResourceGroupName
if ( $null -eq $VNET ) {
    Write-Host -ForegroundColor Yellow "No VNET found in $ResourceGroupName so going to create one"
    
    $SubnetName = Read-Host "SubnetName(ex:MySubnet)"
    $VnetAddressPrefix = Read-Host "Prefix(ex:10.0.0.0/16)"
    $SubnetAddressPrefix = Read-Host "Prefix(ex:10.0.0.0/24)"
    $SingleSubnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName `
        -AddressPrefix $SubnetAddressPrefix

    $VNET = New-AzVirtualNetwork -Name $VnetName -ResourceGroupName $ResourceGroupName 
    -Location $LocationName -AddressPrefix $VnetAddressPrefix -Subnet $SingleSubnet
}

$NSG = Get-AzNetworkSecurityGroup -ResourceName $NSGName -ResourceGroupName $ResourceGroupName 


if ( !( $NSG.SecurityRules | ? destinationPortRange -eq "3389")  ) {
    $NSG | Add-AzNetworkSecurityRuleConfig -Name "Rdp-Rule" -Description "Allow WinRM" -Access "Allow" -Protocol "Tcp" -Direction "Inbound" `
        -Priority 100 -SourceAddressPrefix "Internet" -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange "3389" | Set-AzNetworkSecurityGroup
}

if ( !( $NSG.SecurityRules | ? destinationPortRange -eq "5985-5986")  ) {
    $NSG | Add-AzNetworkSecurityRuleConfig -Name "WinRM-Rule" -Description "Allow WinRM" -Access "Allow" -Protocol "Tcp" -Direction "Inbound" `
        -Priority 150 -SourceAddressPrefix "Internet" -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange "5985-5986" | Set-AzNetworkSecurityGroup
}

$PIP = New-AzPublicIpAddress -Name $PublicIPAddressName -DomainNameLabel $DNSNameLabel -ResourceGroupName $ResourceGroupName `
    -Location $LocationName -AllocationMethod Dynamic -Force

$NIC = New-AzNetworkInterface -Name $NICName -ResourceGroupName $ResourceGroupName `
    -Location $VNET.Location -SubnetId $VNET.Subnets[0].Id -PublicIpAddressId $PIP.Id `
    -NetworkSecurityGroupId $NSG.Id -Force

$VirtualMachine = New-AzVMConfig -VMName $VMName -VMSize $VMSize
$VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $VMName `
    -Credential $Credential -ProvisionVMAgent -EnableAutoUpdate
$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsServer' `
    -Offer 'WindowsServer' -Skus '2019-Datacenter' -Version latest    
$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NIC.Id
$VirtualMachine = Set-AzVMOSDisk -StorageAccountType $storageType -VM $VirtualMachine -CreateOption "FromImage"

Write-Host -ForegroundColor Green "Creating the AZ VM $VMName"

New-AzVm -ResourceGroupName $ResourceGroupName -Location $LocationName `
    -VM $VirtualMachine -Verbose    

Write-Host -ForegroundColor Green "AZ VM $VMName successfully created"

$VirtualMachine = get-AzVm -VMName $VMName

$VirtualMachine | Stop-AzVM -Force

Write-Host -ForegroundColor Green "AZ VM $VMName successfully stopped to add SSD data disk"

$AzDiskConfig = New-AzDiskConfig -Location $LocationName -DiskSizeGB $configdata.DiskSizeGB `
    -AccountType $storageType -CreateOption Empty 

for ($i = 0; $i -lt $configdata.DiskNumber; $i++) {
    $AzDisk = New-AzDisk -ResourceGroupName $ResourceGroupName -Disk $AzDiskConfig `
        -DiskName "$($VMName)_DataDisk$i"
    $VirtualMachine = Add-AzVMDataDisk -Name "$($VMName)_DataDisk$i" -Caching 'ReadWrite' -Lun $i `
        -ManagedDiskId $AzDisk.Id -CreateOption Attach -VM $VirtualMachine
    Write-Host -ForegroundColor Green "AZ VM $VMName SSD Disk $i successfully added"
        
}

Update-AzVM -ResourceGroupName $ResourceGroupName -VM $VirtualMachine

Write-Host -ForegroundColor Green "AZ VM $VMName  successfully updated"

$VirtualMachine | Start-AzVM

Sleep 120

New-Item -ItemType File -Path $env:temp\injectedscript.ps1

$Content = "winrm qc /force
netsh advfirewall firewall add rule name= WinRMHTTP dir=in action=allow protocol=TCP localport=5985
netsh advfirewall firewall add rule name= WinRMHTTPS dir=in action=allow protocol=TCP localport=5986
"
Add-Content $env:temp\injectedscript.ps1 $Content

Write-Host -ForegroundColor Yellow "AZ VM $VMName  Adding WinRM Firewall rules"

Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VMName -ScriptPath $env:temp\injectedscript.ps1 `
    -CommandId 'RunPowerShellScript'

Remove-Item $env:temp\injectedscript.ps1

while ((Invoke-Command $PIP.DnsSettings.Fqdn -Credential $Credential { $env:COMPUTERNAME } `
            -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }  

Invoke-Command $PIP.DnsSettings.Fqdn -Credential $Credential {
    #https://docs.microsoft.com/fr-fr/windows-server/storage/storage-spaces/deploy-standalone-storage-spaces

    $configdata = $args[0]

    $VDiskResiliency = "Simple"

    $disks = Get-physicaldisk | where canpool -eq $true
    $StoragePool = Get-StorageSubsystem | New-StoragePool -Friendlyname MyPool -PhysicalDisks $disks

    $virtualDisk = new-VirtualDisk -StoragePoolFriendlyName $StoragePool.FriendlyName -FriendlyName "VirtualDisk1" `
        -ResiliencySettingName $VDiskResiliency -UseMaximumSize -NumberOfColumns $disks.Count

    $DriveLetter = $configdata.vDiskDriveLetter

    Get-VirtualDisk -FriendlyName $virtualDisk.FriendlyName | Get-Disk | Initialize-Disk -PassThru | New-Partition -DriveLetter $DriveLetter -UseMaximumSize | Format-Volume

    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*.sdn.lab" -Force

    Add-MpPreference -ExclusionExtension "vhd"
    Add-MpPreference -ExclusionExtension "vhdx"

    if (! (Test-Path "$($DriveLetter):\VMs") ) { 
        mkdir "$($DriveLetter):\VMs"
        mkdir "$($DriveLetter):\VMs\Template"
    }
    if (! (Test-Path "$($DriveLetter):\VMs\Template") ) { 
        mkdir "$($DriveLetter):\VMs\Template"
    }

    $AzFileShare = $configdata.AzFileShare
    $AzFQDN = ($AzFileShare).replace("\\", "").split("\")[0]
    $AZFileUser = $configdata.AZFileUser    
    $AZFilePwd = $configdata.AZFilePwd

    #cmdkey /add:$AzFQDN /user:$AZFileUser /pass:$AZFilePwd
    net use Z: $AzFileShare /user:$AZFileUser $AZFilePwd /persistent:yes

    if ( Test-Path "Z:\Template") {
        cp Z:\Template\*.vhdx "$($DriveLetter):\VMs\Template" 
    }
    else{
        Write-Host -ForegroundColor Yellow "Cannot get VHDX Template from $AZFileShare. You need to place it manually to $($DriveLetter):\VMs\Template"
    }

    if ( Test-Path "Z:\apps") {
        cp Z:\apps C: -Recurse 
    }

    Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
} -ArgumentList $configdata

<#
cmdkey /add:microrgsrvnewv092310260.file.core.windows.net /user:Azure\microrgsrvnewv092310260 /pass:w78qJNa3j46hmXpDY+D6DL0286n/5s+ePP3swCvNNX3KR28gDZCA3OBadKb3XUX+whNkP3m2mEmVV+FQ9HEThA==
net use Z: \\microrgsrvnewv092310260.file.core.windows.net\sdntemplate / persistent:Yes
#>

Write-Host -ForegroundColor Green "AZ VM $VMName is running and can be RDP on $($PIP.DnsSettings.Fqdn)"
Write-Host "mstsc /v:$($PIP.DnsSettings.Fqdn)"

Write-Host -ForegroundColor Yellow `
    "You are ready to deploy SDN Stack. Before running the SDNNEsted.ps1 script please ensure to have VHD template uploaded to the AzureVM"
