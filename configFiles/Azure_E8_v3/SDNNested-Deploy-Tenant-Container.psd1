@{
    ScriptVersion        = "2.0"

    VHDPath              = "Z:"
    VHDFile              = "Win2019-Core.vhdx"
    #Where Tenants VMs will be stored, generally same than the SDNExpressConfig
    VMLocation           = "D:\VMs"
    #Has to match with the folder name 
    ConfigFileName       = "VMAS"

    ProductKey           = ''

    VMMemory             = 2GB
    VMProcessorCount     = 2
    SwitchName           = "SDNSwitch"

    HYPV                 = @("SDN-HOST01.SDN.LAB", "SDN-HOST02.SDN.LAB")

    DomainJoinUserName   = "SDN\administrator"
    LocalAdminDomainUser = "SDN\administrator"

    RestURI = "https://NCNORTHBOUND.SDN.LAB"

    Tenants              = 
    @(
        @{
            Name                              = "Contoso";
            TenantVirtualNetworkName          = "VNET-Tenant-Contoso"
            TenantVirtualNetworkAddressPrefix = @("172.16.0.0/16") 
            PhysicalGwVMName                  = 'CONTOSO-GW01'
            
            TenantVirtualSubnets              = 
            @( 
                    @{      
                        Name    =  "VSUBNET-Tenant-Contoso-WebTier";
                        AddressPrefix = "172.16.1.0/24"
                    },
                    @{      
                        Name    =  "VSUBNET-Tenant-Contoso-vGW";
                        AddressPrefix = "172.16.255.0/24"
                    }
            )
            DomainFQDN                        = ""
        },
        @{
            Name                              = "Fabrikam";
            TenantVirtualNetworkName          = "VNET-Tenant-Fabrikam"
            TenantVirtualNetworkAddressPrefix = @("172.16.0.0/16") 
            PhysicalGwVMName                  = 'FABRIKAM-GW01'
            
            TenantVirtualSubnets              = 
            @( 
                    @{      
                        Name    =  "VSUBNET-Tenant-Fabrikam-WebTier";
                        AddressPrefix = "172.16.1.0/24"
                    },
                    @{      
                        Name    =  "VSUBNET-Tenant-Fabrikam-vGW";
                        AddressPrefix = "172.16.255.0/24"
                    }
            )
            DomainFQDN                        = ""
        }
    )

    #
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
            RouteDstPrefix              = @( "172.16.254.0/24", "2.2.2.2/32" )
            #BGP Router properties  
            BGPEnabled                  = $True;
            BgpLocalExtAsNumber         = "0.64512"   
            BgpLocalBRouterId           = ""   
            BgpLocalRouterIP            = @()
            BgpPeerIpAddress            = "2.2.2.2"   
            BgpPeerAsNumber             = 64521   
            BgpPeerExtAsNumber          = "0.64521"   
        },
        <#@{
            Tenant              = "Fabrikam"
            Capacity            = 10000 #In KBytes/s
            Type                = 'GRE'
            VirtualGwName       = 'Fabrikam_vGW'
            RouteDstPrefix      = @( "172.16.254.0/24", "2.2.2.2/32" )
            PSK                 = "1234"
            GrePeer             = "1.1.1.1"
            #BGP Router properties  
            BGPEnabled          = $true
            BgpLocalExtAsNumber = "0.64512"   
            BgpLocalBRouterId   = ""   
            BgpLocalRouterIP    = @()
            BgpPeerIpAddress    = "2.2.2.2"   
            BgpPeerAsNumber     = 64521   
            BgpPeerExtAsNumber  = "0.64521"   
        },#>
        @{
            Tenant              = "Fabrikam"
            Type                = 'IPSEC'
            VirtualGwName       = 'Fabrikam_vGW'
            RouteDstPrefix      = @( "192.168.254.0/24", "4.4.4.4/32" )
            PSK                 = "Password1"
            AuthenticationMethod = "PSK"
            IPSecPeer           = "3.3.3.3"
            #BGP Router properties  
            BGPEnabled          = $true
            BgpLocalExtAsNumber = "0.64512"   
            BgpLocalBRouterId   = ""   
            BgpLocalRouterIP    = @()
            BgpPeerIpAddress    = "4.4.4.4"   
            BgpPeerAsNumber     = 64521   
            BgpPeerExtAsNumber  = "0.64521"
        }
    )
    
    #Tenants VMs
    TenantVMs            = 
    @(
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            VHDFile      = "Win2019-Core-Container.vhdx"
            Tenant       = "Contoso"
            Name         = 'Contoso-CH01'
            VMMemory             = 4GB
            VMProcessorCount     = 4
            # ContainerHost is not a Windows role but it will be used from the deployment script
            # to make right decision
            roles        = @("ContainerHost")   
            # IMPORTANT : The IP pool of Containers (L2BRIDGE) running behind the VMNIC
            # Below 2^3 - 1 = 7 additionnal addresses will be pushed to the NC API
            # 7 IIS containers will be run and load balanced - see VIP IP addr above   
            ContainersIpPool = "172.16.1.32/29"             
            NICs         = @( 
                @{ 
                    Name = "Ethernet"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @("") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   

        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            VHDFile      = "Win2019-Core-Container.vhdx"
            Tenant       = "Contoso"
            Name         = 'Contoso-CH02'
            VMMemory             = 4GB
            VMProcessorCount     = 4
            # ContainerHost is not a Windows role but it will be used from the deployment script
            # to make right decision
            roles        = @("ContainerHost")
            # IMPORTANT : The IP pool of Containers (L2BRIDGE) running behind the VMNIC
            # Below 2^3 - 1 = 7 additionnal addresses will be pushed to the NC API
            # 7 IIS containers will be run and load balanced - see VIP IP addr above   
            ContainersIpPool = "172.16.1.40/29"             
            NICs         = @( 
                @{ 
                    Name = "Ethernet"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @("") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            VHDFile      = "Win2019-Core-Container.vhdx"
            Tenant       = "Fabrikam"
            Name         = 'Fabrikam-CH01'
            VMMemory             = 4GB
            VMProcessorCount     = 4
            roles        = @("ContainerHost")
            ContainersIpPool = "172.16.1.32/29"            
            NICs         = @( 
                @{ 
                    Name = "Ethernet"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @("") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            VHDFile      = "Win2019-Core-Container.vhdx"
            Tenant       = "Fabrikam"
            Name         = 'Fabrikam-CH02'                        
            VMMemory             = 4GB
            VMProcessorCount     = 4
            ContainersIpPool = "172.16.1.40/29"                 
            roles        = @("ContainerHost")
            NICs         = @( 
                @{ 
                    Name = "Ethernet"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @("") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        }
    )

    #SLB configuration
    SlbVIPs                 =
    @(
        @{
            Tenant              = "Contoso"
            Name                = 'Contoso-WebRainbow'
            VIP                 = "41.40.40.8"
            VIPAllocationMethod = "static" 
            FrontendPort        = 80
            BackendPort         = 80   
            Protocol            = "TCP"
            TenantVMs           = @("Contoso-CH01", "Contoso-CH02")     
        },
        @{
            Tenant              = "Fabrikam"
            Name                = 'Fabrikam-WebRainbow'
            VIP                 = "41.40.40.9"
            VIPAllocationMethod = "static" 
            FrontendPort        = 80
            BackendPort         = 80
            Protocol            = "TCP"
            TenantVMs           = @("Fabrikam-CH01", "Fabrikam-CH02")  
        }
    )

    OutboundNAT = 
    @(
        @{
            Tenant              = "Contoso"
            Name                = 'OutboundNAT'
            VIPAllocationMethod = "static" 
            VIP                 = "41.40.40.18"
            TenantVMs           = @("Contoso-CH01", "Contoso-CH02")     
        },
        @{
            Tenant              = "Fabrikam"
            Name                = 'OutboundNAT'
            VIPAllocationMethod = "static" 
            VIP                 = "41.40.40.19"
            TenantVMs           = @("Fabrikam-CH01", "Fabrikam-CH02")  
        }
    )    
}