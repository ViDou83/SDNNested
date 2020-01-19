@{
    ScriptVersion        = "2.0"

    VHDPath              = "F:\VMs\Template"
    VHDFile              = "Win2019-Core.vhdx"
    VHDGUIFile           = "Win2019-GUI.vhdx"

    VMLocation           = "F:\VMs"
    DomainFQDN           = "SDN.LAB"

    ManagementSubnet     = "10.184.108.0/24"
    ManagementGateway    = "10.184.108.1"
    ManagementDNS        = @("10.184.108.1")
    ManagementVLANID     = 7

    DomainJoinUsername   = "SDN\administrator"
    LocalAdminDomainUser = "SDN\administrator"

    VMHostadmin         = "vidou"
    VMHostPwd           = "Azertyuiop!01"

    #IMPORTANT VMs will be stored on S2D storage pool (bad perf with NESTED virtualization)
    SDNonS2D          = $true

    HostSdnNICs     = 
    @( 
        @{ Name = "SdnMgmt"; IPAddress = '10.184.108.50/24'; Gateway = ''; DNS = @("10.184.108.1") ; VLANID = 7 };
        @{ Name = "SdnPa"; IPAddress = '10.10.56.50/23'; Gateway = ''; DNS = @("10.184.108.1") ; VLANID = 11 };
    )   

    DCs                  = 
    @(
        @{
            ComputerName = 'SDN-DC01';
            VMMemory     = 4GB;
            VMProcessorCount = 2;
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.1/24'; Gateway = ''; DNS = '' ; VLANID = 7 }
            )   
        }
    )

    HyperVHosts          = 
    @(
        @{
            ComputerName = 'SDN-HOST01'; 
            VMMemory     = 52GB;
            VMProcessorCount = 8;
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.2/24'; Gateway = '10.184.108.1'; DNS = @("10.184.108.1") ; VLANID = 7 };
            )   
        },   
        @{
            ComputerName = 'SDN-HOST02'; 
            VMMemory     = 52GB;
            VMProcessorCount = 8;
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.184.108.3/24'; Gateway = '10.184.108.1'; DNS = @("10.184.108.1") ; VLANID = 7 };
            )   
        }
    )

    TenantInfraGWs                  = 
    @(
        @{
            Tenant       = "Contoso"
            ComputerName = 'Contoso-GW01' 
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.127.134.65/25'; Gateway = '10.127.134.55'; DNS = @("10.184.108.1") ; VLANID = 1001 };
            )   
        },   
        @{
            Tenant       = "Fabrikam"
            ComputerName = 'Fabrikam-GW01'
            NICs         = @( 
                @{ Name = "Ethernet"; IPAddress = '10.10.56.250/23'; Gateway = '10.10.56.1'; DNS = @("10.184.108.1") ; VLANID = 11 };
            )   
        }
    )

    TenantvGWs           =
    @(
        @{
            Tenant                      = "Contoso"
            Type                        = 'L3'
            VirtualGwName               = 'Contoso_vGW'
            LogicalNetworkName          = "Contoso_L3_Interco_Network"
            LogicalSunetName            = "Contoso_L3_Interco_Subnet"
            VLANID                      = 1001;
            LogicalSunetAddressPrefix   = "10.127.134.0/25"
            LogicalSunetDefaultGateways = "10.127.134.1"
            LocalIpAddrGW               = "10.127.134.55"
            PeerIpAddrGW                = @( "10.127.134.65" )
            RouteDstPrefix              = @( "1.1.1.1/32" )
            #BGP Router properties  
            BGPEnabled                  = $True;
            BgpLocalExtAsNumber         = "0.64512"   
            BgpLocalBRouterId           = "10.127.134.55"   
            BgpLocalRouterIP            = @("10.127.134.55")
            BgpPeerIpAddress            = "10.127.134.65"   
            BgpPeerAsNumber             = 64521   
            BgpPeerExtAsNumber          = "0.64521"   
        },
        @{
            Tenant              = "Fabrikam"
            Type                = 'GRE'
            VirtualGwName       = 'Fabrikam_vGW'
            RouteDstPrefix      = @( "172.16.0.0/16" )
            #BGP Router properties  
            PSK                 = "1234"
            GrePeer             = "1.1.1.1"
            BGPEnabled          = $true
            BgpLocalExtAsNumber = "0.64512"   
            BgpLocalBRouterId   = "Fabrikam_vGW"   
            BgpLocalRouterIP    = @("172.16.179.179")
            BgpPeerIpAddress    = "172.16.254.50"   
            BgpPeerAsNumber     = 64521   
            BgpPeerExtAsNumber  = "0.64521"   
        }
    )

    
    TORrouter = 
    @(
        @{
            ComputerName = 'SDN-TORGW'; 

            NICs    = @( 
                            @{ Name = "Ethernet"; IPAddress = '10.10.56.1/23'; Gateway = ''; DNS = '' ; VLANID = 11 };
                            @{ Name = "Ethernet 2"; IPAddress = '10.184.108.254/24'; Gateway = ''; DNS = '' ; VLANID = 7 };
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
                @{  Route = "1.1.1.1/32"; NextHop = '10.10.56.250'; }
            )
        }
    )


    #If SDNonS2D          = $False then the S2DDiskSize and S2DDiskNumber will be ignored
    S2DDiskSize          = 128GB
    S2DDiskNumber        = 3
    S2DClusterIP         = "10.184.108.4"
    S2DClusterName       = "SDNFABRIC"
   
    ProductKey           = 'T99NG-BPP9T-2FX7V-TX9DP-8XFB4'

    # Switch name is only required if more than one virtual switch exists on the Hyper-V hosts.
    # SwitchName=''

    # Amount of Memory and number of Processors to assign to VMs that are created.
    # If not specified a default of 8 procs and 8GB RAM are used.
    VMMemory             = 2GB
    VMProcessorCount     = 2

    SwitchName           = "SDN"

    PublicVIPNetRoute         = @{ Destination =   "41.40.40.0/27"; NextHop = "10.184.108.254"; }

    # If Locale and Timezone are not specified the local time zone of the deployment machine is used.
    # Locale           = ''
    # TimeZone         = ''

    # Passowrds can be optionally included if stored encrypted as text encoded secure strings.  Passwords will only be used
    # if SDN Express is run on the same machine where they were encrypted, otherwise it will prompt for passwords.
    # DomainJoinSecurePassword  = ''
    # LocalAdminSecurePassword   = ''
    # NCSecurePassword   = ''

}