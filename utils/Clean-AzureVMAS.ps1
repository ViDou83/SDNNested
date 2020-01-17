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

.EXAMPLE

.EXAMPLE

.EXAMPLE

.NOTES

#>

Write-SDNExpressLog  "Stopping all running VMs"
get-vm | stop-vm -Force
Write-SDNExpressLog  "Removing all running VMs"
get-vm | remove-vm -Force

Write-SDNExpressLog  "Removing all vmswitches"
Get-VMSwitch | Remove-VMSwitch -Force

Restart-Service vmms -Force

$partitions=Get-Partition | ? DriveLetter
foreach($part in $partitions){
    if($part.size -gt 1TB){
       Write-SDNNestedLog  "Cleaning drive $($part.DriveLetter) where VMs VHDX are stored"
        Remove-Item "$($part.DriveLetter):\*" -Force -Recurse
        New-Item -Type Directory "$($part.DriveLetter):\VMs"
        New-Item -Type Directory "$($part.DriveLetter):\VMs\Template" 
    }
}

Write-SDNExpressLog  "Removing DataDepu and restart"
Get-WindowsFeature | ? Name -eq FS-Data-Deduplication | Uninstall-WindowsFeature -Restart