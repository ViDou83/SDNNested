@{

    ScriptVersion               = "2.0"

    # Azure VM size 
    VMSize                     = "Standard_E16_v3"

    #Below define the Azure VMName, you can use the script cmd line to define it as well
    #VMName                      = "SDN-011820"
    
    #Azure VM credential - if note defined will be prompted
    #VMLocalAdminUser            = "Localuser"
    #VMLocalAdminSecurePassword  = "MyVeryComplexPassword" 

    # Azure Account information
    # recommendation would be to create it from portal 1st otherwise, you will be prompted
    ResourceGroupName           = "RG-AZ-FRANCE"
    VnetName                    = "VNET1-AZ-FRANCE"
    SubnetName                  = "AzFranceSubnet"
    
    #subscription                = "Microsoft Azure Internal Consumption"
    #Azure StorageType
    storageType                 = 'StandardSSD_LRS'

    #Network Security Group where the VM will get (RDP and RemoteWinRM will be allowed!!!!)
    NSGName                     = "NSG-AZ-FRANCE" 

    # Azure VM Disk number and size 
    # Below 8 Disks with 128GB will be aggregated to one vDISK of 1TB
    # It helps to maximize IOPS
    DiskNumber                  = 8
    DiskSizeGB                  = 128
    
    # Remote share where the VHDX template are located. 
    # Share name Tree structure must be 
    #    \\FQDN\sdntemplate
    #                       \template\*.VHDX
    #                       \apps\*.exe 
    # In my case, I'm using an Azure File Share
    # AzureVM Drive letter where VHDX will be copied 
    
    vDiskDriveLetter            = "F:"
    #If not provided, will be ignored
    #AZFileShare                 = "\\myshare.file.core.windows.net\sndtemplate"
    #AZFileUser                  = "Azure\myuser"
    #AZFilePwd                   = "MyVeryComplexPassword"
}