@{
    ScriptVersion        = "2.0"

    VHDPath              = "Z:"
    VHDFile              = "Win2019-Core.vhdx"
    VMLocation           = "D:\VMs"
    
    ConfigFileName       = "Azure_E16_v3"

    ProductKey           = 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'

    VMMemory             = 2GB
    VMProcessorCount     = 2
    SwitchName           = "SDNSwitch"

    HYPV                 = @("SDN-HOST01.SDN.LAB", "SDN-HOST02.SDN.LAB")

    DomainJoinUserName   = "SDN\administrator"
    LocalAdminDomainUser = "SDN\administrator"

    RestURI = "https://NORTHBOUNDAPI.SDN.LAB"

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
        },
        @{
            Name                              = "Acme";
            TenantVirtualNetworkName          = "VNET-Tenant-Acme"
            TenantVirtualNetworkAddressPrefix = @("172.16.0.0/16") 
            PhysicalGwVMName                  = 'ACME-GW01'
            
            TenantVirtualSubnets              = 
            @( 
                    @{      
                        Name    =  "VSUBNET-Tenant-Acme-WebTier";
                        AddressPrefix = "172.16.1.0/24"
                    },
                    @{      
                        Name    =  "VSUBNET-Tenant-Acme-vGW";
                        AddressPrefix = "172.16.255.0/24"
                    }
            )
            DomainFQDN                        = ""
        }
    )

    TenantvGWs           =
    @(
        @{
            Tenant                      = "Contoso"
            Type                        = 'L3'
            VirtualGwName               = 'Contoso_vGW'
            Capacity                    = 100000 
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
        @{
            Tenant              = "Fabrikam"
            Type                = 'IPSEC'
            Capacity            = 100000 
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
        },
        @{
            Tenant              = "Acme"
            Type                = 'GRE'
            Capacity            = 100000 
            VirtualGwName       = 'Acme_vGW'
            RouteDstPrefix      = @( "10.16.254.0/24", "6.6.6.6/32" )
            PSK                 = "1234"
            GrePeer             = "5.5.5.5"
            #BGP Router properties  
            BGPEnabled          = $true
            BgpLocalExtAsNumber = "0.64512"   
            BgpLocalBRouterId   = ""   
            BgpLocalRouterIP    = @()
            BgpPeerIpAddress    = "6.6.6.6"   
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
            NICs         = @( 
                @{ 
                    Name = "Contoso-NetAdapter"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            Tenant       = "Contoso"
            Name         = 'Contoso-VM02'
            Subnet       =  "VSUBNET-Tenant-Contoso-WebTier";
            roles        = @("Web-Server", "Web-Mgmt-Service")
            NICs         = @( 
                @{ 
                    Name = "Contoso-NetAdapter"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            Tenant       = "Fabrikam"
            Name         = 'Fabrikam-VM01'
            roles        = @("Web-Server", "Web-Mgmt-Service")   
            Subnet       =  "VSUBNET-Tenant-Fabrikam-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Fabrikam-NetAdapter"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            Tenant       = "Fabrikam"            
            Name         = 'Fabrikam-VM02'
            roles        = @("Web-Server", "Web-Mgmt-Service")            
            Subnet       =  "VSUBNET-Tenant-Fabrikam-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Fabrikam-NetAdapter"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        },
        @{
            HypvHostname = "SDN-HOST02.SDN.LAB"
            Tenant       = "Acme"
            Name         = 'Acme-VM01'
            roles        = @("Web-Server", "Web-Mgmt-Service")   
            Subnet       =  "VSUBNET-Tenant-Acme-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Acme-NetAdapter"; IPAddress = '172.16.1.10/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )
        },
        @{
            HypvHostname = "SDN-HOST01.SDN.LAB"
            Tenant       = "Acme"            
            Name         = 'Acme-VM02'
            roles        = @("Web-Server", "Web-Mgmt-Service")            
            Subnet       =  "VSUBNET-Tenant-Acme-WebTier";
            NICs         = @( 
                @{ 
                    Name = "Acme-NetAdapter"; IPAddress = '172.16.1.11/24'; Gateway = '172.16.1.1'; 
                    DNS = @() ; MACAddress = '00-00-00-00-00-00'; VLANID = 0 
                };
            )   
        }
    )

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
            Tenant              = "Acme"
            Name                = 'Acme-WebRainbow'
            VIP                 = "41.40.40.10"
            VIPAllocationMethod = "static" 
            FrontendPort        = 80
            BackendPort         = 80
            Protocol            = "TCP"
            TenantVMs           = @("Acme-VM01", "Acme-VM02")  
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
        },
        @{
            Tenant              = "Acme"
            Name                = 'OutboundNAT'
            VIPAllocationMethod = "static" 
            VIP                 = "41.40.40.20"
            TenantVMs           = @("Acme-VM01", "Acme-VM02")  
        }
    )    
}