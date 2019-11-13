#https://docs.microsoft.com/fr-fr/windows-server/storage/storage-spaces/deploy-standalone-storage-spaces
$VDiskResiliency = "Simple"

$disks = Get-physicaldisk | where canpool -eq $true
$StoragePool = Get-StorageSubsystem | New-StoragePool -Friendlyname MyPool -PhysicalDisks $disks
    
$virtualDisk = new-VirtualDisk –StoragePoolFriendlyName $StoragePool.FriendlyName –FriendlyName VirtualDisk1 –ResiliencySettingName $VDiskResiliency –UseMaximumSize -NumberOfColumns $disks.Count

Get-VirtualDisk –FriendlyName $virtualDisk.FriendlyName | Get-Disk | Initialize-Disk –Passthru | New-Partition –AssignDriveLetter –UseMaximumSize | Format-Volume

Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*.sdn.lab" -Force

Add-MpPreference -ExclusionExtension "vhd"
Add-MpPreference -ExclusionExtension "vhdx"

#Install HYPV
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart