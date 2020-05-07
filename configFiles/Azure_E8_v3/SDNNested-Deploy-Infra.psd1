@{
    ScriptVersion        = "2.0"

    VHDPath              = "E:\VMs\Template"
    #The VHD file name has to match with the one located on the above path
    VHDFile              = "Win2019-Core.vhdx"
    VHDGUIFile           = "Win2019-GUI.vhdx"
    VMLocation           = "E:\VMs"
    
    #Domain of the SDN infrastructure (NC/MUX/GW will be joined)
    DomainFQDN           = "SDN.LAB"
    #IP PLAN
    ManagementSubnet     = "10.184.108.0/24"
    ManagementGateway    = "10.184.108.1"
    ManagementDNS        = @("10.184.108.1")
    ManagementVLANID     = 7

    #Domain users infos
    DomainJoinUsername   = "SDN\administrator"
    LocalAdminDomainUser = "SDN\administrator"

    #Put the Username and Password of the Local Machine where SDNNested will be deploy
    #In case of Azure, this is the Azure VM cred 
    VMHostadmin          = "Localuser"
    VMHostPwd            = "MyVeryComplexPassword"

    #IMPORTANT VMs will be stored on S2D storage pool (bad perf with NESTED virtualization)
    S2DEnabled          = $False

    # If SDNonS2D          = $False 
    # then the S2DDiskSize and S2DDiskNumber will be ignored
    # otherwise disk will be created and used to store VMs
    S2DDiskSize          = 128GB
    S2DDiskNumber        = 3
    S2DClusterIP         = "10.184.108.4"
    # Please use this name to add the cluster to WAC (eg. SDNFABRIC.SDN.LAB)
    S2DClusterName       = "SDNFABRIC"
   
    #Product Key of VMs
    ProductKey           = 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'

    # Switch name is only required if more than one virtual switch exists on the Hyper-V hosts.
    SwitchName           = "SDN"

    # Amount of Memory and number of Processors to assign to VMs that are created.
    # If not specified a default of 8 procs and 8GB RAM are used.
    # Can be overloaded at VMs level
    VMMemory             = 2GB
    VMProcessorCount     = 2

    #If you want SDN VM's getting Internet access from VMHOST
    ShareHostInternet = $true

    #Adding Mirroring of the SDN stack
    PortMirroring = $true

    #LOCAL MACHINE / AZURE VM SDN vNICs 
    VMHostvNICs     = 
    @( 
        @{ SwitchName="SDN"; Name = "SdnMgmt"; IPAddress = '10.184.108.50/24'; Gateway = ''; DNS = @("10.184.108.1") ; VLANID = 7; 
                NetRoute = @{ Destination =   "41.40.40.0/27"; NextHop = "10.184.108.1"; }
        };
        @{ SwitchName="SDN"; Name = "SdnPa"; IPAddress = '10.10.56.50/23'; Gateway = ''; DNS = @("") ; VLANID = 11; NetRoute =""; };
        #Third regarding Internet access on SDN Stack to uncomment if  ShareHostInternet = $true
        @{ SwitchName="Internet"; Name = "Internet"; IPAddress = '192.168.1.1/24'; Gateway = ''; DNS = @("") ; VLANID = 2;  NetRoute =""; };
    )   

    #DCs, HYPV HOSTs (where SDN stack will be deployed), ToR Router and Tenants External GWs def 
    DCs                  = 
    @(
        @{
            ComputerName = 'SDN-DC01';
            VMMemory     = 2GB;
            VMProcessorCount = 2;
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.1/24'; Gateway = ''; DNS = '' ; VLANID = 7 },                #Second in case if ToR is going to be deployed 
                #Second in case if ToR is going to be deployed 
                @{ Name = "Ethernet 2"; IPAddress = '10.10.56.1/24'; Gateway = ''; DNS = '' ; VLANID = 11 };
                #Third regarding Internet access on SDN Stack to uncomment if  ShareHostInternet = $true
                @{ Name = "Ethernet 3"; IPAddress = '192.168.1.254/24'; Gateway = '192.168.1.1'; DNS = '' ; VLANID = 2 };
            )   
        }
    )

    HyperVHosts          = 
    @(
        @{
            ComputerName = 'SDN-HOST01'; 
            VMMemory     = 26GB;
            VMProcessorCount = 4;
            VMDiskSize = 384GB; #Will be ignore is SDNonS2D is $true
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.2/24'; Gateway = '10.184.108.1'; DNS = @("10.184.108.1") ; VLANID = 7 };
            )   
        },   
        @{
            ComputerName = 'SDN-HOST02'; 
            VMMemory     = 24GB;
            VMProcessorCount = 4;
            VMDiskSize = 384GB; #Will be ignore is SDNonS2D is $true
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.3/24'; Gateway = '10.184.108.1'; DNS = @("10.184.108.1") ; VLANID = 7 };
            )   
        }
    )

    #External Tenant GWs - simulate external connectivity
    TenantInfraGWs                  = 
    @(
        @{
            Tenant       = "Contoso"
            ComputerName = 'Contoso-GW01' 
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.127.134.65/25'; Gateway = ''; DNS = @("10.184.108.1") ; VLANID = 1001 };
            )   
        },   
        @{
            Tenant       = "Fabrikam"
            ComputerName = 'Fabrikam-GW01'
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.10.56.250/23'; Gateway = ''; DNS = @("10.184.108.1") ; VLANID = 11 };
            )   
        }
    )

    # Top of Rack (ToR) router configuration 
    # if ComputerName is existing VMs (eg. DC), deploy RRAS on it and configure BGP and so on 
    # otherwise deploy a dedicated VM
    # In case of existing VMs, all ToRrouter attributes will be ignored, it means that the PA NIC has to be declared (see commnet on above in DC Hash)
    TORrouter = 
    @(
        @{
            #ComputerName = 'SDN-TORGW'; 
            ComputerName = 'SDN-DC01'; 

            InternetNAT         = $true
  
            NICs    = 
            @( 
                @{ Name = "Ethernet"; IPAddress = '10.10.56.1/23'; Gateway = ''; DNS = '' ; VLANID = 11 };
                @{ Name = "Ethernet 2"; IPAddress = '10.184.108.254/24'; Gateway = ''; DNS = '' ; VLANID = 7 };
                @{ Name = "Ethernet 3"; IPAddress = '192.168.1.254/24'; Gateway = '192.168.1.1'; DNS = '' ; VLANID = 2 };
            )

            SDNASN       = '64628'
            BgpRouter      = @(
                @{
                    RouterASN       = '64623'
                    RouterIPAddress = '10.10.56.1'
                }
            )

            BgpPeers      = @(
                @{  Name = "SDN-MUX01"; PeerIPAddress = '10.10.56.6'; },
                @{  Name = "SDN-MUX02"; PeerIPAddress = '10.10.56.7'; },
                @{  Name = "SDN-GW01"; PeerIPAddress = '10.10.56.8'; },
                @{  Name = "SDN-GW02"; PeerIPAddress = '10.10.56.9'; };
            )

            StaticRoutes = @(
                @{  Route = "1.1.1.1/32"; NextHop = '10.10.56.250'; },
                @{  Route = "3.3.3.3/32"; NextHop = '10.10.56.250'; }
            )
        }
    )
 
    # If Locale and Timezone are not specified the local time zone of the deployment machine is used.
    # Locale           = ''
    # TimeZone         = ''

    # Passowrds can be optionally included if stored encrypted as text encoded secure strings.  Passwords will only be used
    # if SDN Express is run on the same machine where they were encrypted, otherwise it will prompt for passwords.
    # DomainJoinSecurePassword  = ''
    # LocalAdminSecurePassword   = ''
    # NCSecurePassword   = ''
}