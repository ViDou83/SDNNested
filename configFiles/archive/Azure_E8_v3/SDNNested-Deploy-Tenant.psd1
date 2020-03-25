@{
    ScriptVersion        = "2.0"

    VHDPath              = "Z:"
    VHDFile              = "Win2019-Core.vhdx"
    #Where Tenants VMs will be stored, generally same than the SDNExpressConfig
    VMLocation           = "D:\VMs"
    #Has to match with the folder name 
    ConfigFileName       = "Azure_E8_v3"

    ProductKey           = 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'

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
            DomainFQDN                        = "contoso.local"
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
            DomainFQDN                        = "fabrikam.local"
        }
    )

    #This block must be the same the one defined on SDNNested-Infra.psd1 to have everyhting auto-configured 
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
            RouteDstPrefix              = @( "172.16.254.0/24", "1.1.1.1/32", "2.2.2.2/32" )
            #BGP Router properties  
            BGPEnabled                  = $True;
            BgpLocalExtAsNumber         = "0.64512"   
            BgpLocalBRouterId           = "Contoso_vGW"   
            BgpLocalRouterIP            = @()
            BgpPeerIpAddress            = "2.2.2.2"   
            BgpPeerAsNumber             = 64521   
            BgpPeerExtAsNumber          = "0.64521"   
        },
        @{
            Tenant              = "Fabrikam"
            Type                = 'GRE'
            VirtualGwName       = 'Fabrikam_vGW'
            RouteDstPrefix      = @( "172.16.254.0/24", "2.2.2.2/32" )
            PSK                 = "1234"
            GrePeer             = "1.1.1.1"
            #BGP Router properties  
            BGPEnabled          = $true
            BgpLocalExtAsNumber = "0.64512"   
            BgpLocalBRouterId   = "Fabrikam_vGW"   
            BgpLocalRouterIP    = @()
            BgpPeerIpAddress    = "2.2.2.2"   
            BgpPeerAsNumber     = 64521   
            BgpPeerExtAsNumber  = "0.64521"   
        }
    )

    TenantVMs            = 
    @(
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            Tenant       = "Contoso"
            Name         = 'Contoso-VM01'
            Subnet       =  "VSUBNET-Tenant-Contoso-WebTier";
            roles        = @("Web-Server", "Web-Mgmt-Service")
            VIP          = "41.40.40.8"             
            NICs         = @( 
                @{ 
                    Name = "Contoso-NetAdapter"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @("172.16.1.53") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            Tenant       = "Contoso"
            Name         = 'Contoso-VM02'
            Subnet       =  "VSUBNET-Tenant-Contoso-WebTier";
            roles        = @("Web-Server", "Web-Mgmt-Service")
            VIP          = "41.40.40.8"             
            NICs         = @( 
                @{ 
                    Name = "Contoso-NetAdapter"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @("172.16.1.53") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            Tenant       = "Fabrikam"
            Name         = 'Fabrikam-VM01'
            roles        = @("Web-Server", "Web-Mgmt-Service")   
            VIP          = "41.40.40.9"
            Subnet       =  "VSUBNET-Tenant-Fabrikam-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Fabrikam-NetAdapter"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @("172.16.1.53") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            Tenant       = "Fabrikam"            
            Name         = 'Fabrikam-VM02'
            roles        = @("Web-Server", "Web-Mgmt-Service")            
            VIP          = "41.40.40.9"
            Subnet       =  "VSUBNET-Tenant-Fabrikam-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Fabrikam-NetAdapter"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @("172.16.1.53") ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
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
            TenantVMs           = @("Contoso-VM01", "Contoso-VM02")     
        },
        @{
            Tenant              = "Fabrikam"
            Name                = 'Fabrikam-WebRainbow'
            VIP                 = "41.40.40.9"
            VIPAllocationMethod = "static" 
            FrontendPort        = 80
            BackendPort         = 80
            Protocol            = "TCP"
            TenantVMs           = @("Fabrikam-VM01", "Fabrikam-VM02")  
        },
        @{
            Tenant              = "Fabrikam"
            Name                = 'Fabrikam-WebRainbow'
            VIP                 = "41.40.40.9"
            VIPAllocationMethod = "static" 
            FrontendPort        = 80
            BackendPort         = 80
            Protocol            = "TCP"
            TenantVMs           = @("Fabrikam-VM01", "Fabrikam-VM02")  
        }
    )

    OutboundNAT = 
    @(
        @{
            Tenant              = "Contoso"
            Name                = 'OutboundNAT'
            VIPAllocationMethod = "static" 
            VIP                 = "41.40.40.18"
            TenantVMs           = @("Contoso-VM01", "Contoso-VM02")     
        },
        @{
            Tenant              = "Fabrikam"
            Name                = 'OutboundNAT'
            VIPAllocationMethod = "static" 
            VIP                 = "41.40.40.19"
            TenantVMs           = @("Fabrikam-VM01", "Fabrikam-VM02")     
        }
    )
    
}