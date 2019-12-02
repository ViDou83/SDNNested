@{

    ScriptVersion               = "2.0"

    # Credentials for Local Admin account you created in the sysprepped (generalized) vhd image
    #VMSize                     = "Standard_E8_v3"
    VMSize                      = "Standard_E16_v3"

    VMName                      = "SDN-11282019"
    VMLocalAdminUser            = "vidou"
    VMLocalAdminSecurePassword  = "Azertyuiop!01" 
    ## Azure Accoun t
    LocationName                = "FranceCentral"
    ResourceGroupName           = "RG-AZ-FRANCE"
    VnetName                    = "VNET1-AZ-FRANCE"
    SubnetName                  = "SUB-ARM-SRV-WIN"
    #SecurityGroupName          = "$($VMName)_NetSecurityGroup"
    #PublicIPAddressName        = "$($VMName)_PIP1"
    subscription                = "Microsoft Azure Internal Consumption"
    #NICName                    = "$($VMName)_NIC1"
    #DNSNameLabel               = $VMName
    storageType                 = 'StandardSSD_LRS'

    NSGName                     = "NSG-AZ-FRANCE" 

    DiskNumber                  = 8
    DiskSizeGB                  = 128
    vDiskDriveLetter            = 'F'
    AZFileShare                 = "\\rgazfrancediag.file.core.windows.net\sndtemplate"
    AZFileUser                  = "Azure\rgazfrancediag"
    AZFilePwd                   = "U6PEMjWhJ3D0eZb1EfINfTsk4hUsUF30Wg0yVJb+ezA9KUgQBjv8VWoju2UfQQqi4WB7lGzYA3BAzZlAbs/weQ=="
}