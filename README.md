# Purpose 
SDNNested is a collection of Powershell Scrits that helps to automate the deployment of a Microsoft SDNv2 LAB on one single machine (Nested LAB). 

https://docs.microsoft.com/en-us/windows-server/networking/sdn/software-defined-networking
 
![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/diagram_new.jpg?raw=true)
![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/legende.jpg?raw=true)

# General requirement
*   HYPV role is required (Nested Virtualization will be use) 
*   A minimum of 64GB of RAM (use config file under .\configfiles\Azure_E8_v3 )
*   A minimum of 1TB of storage to store VMs is recommended
    *   From configfiles examples, the Drive is F: but it can be changed. 
*   MAchine's processor(s) must support Nested Virtualization  :
    *   see https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization
    
## Example of deployed infrastucture
IMPORTANT: To be sucessful, it is recommended to understand config files structure before start a deployement.

You can either use provided config files or simply copy one folder and rename it based on your need (in that case config files structure needs to be well understood).


VM acting as Hypv Server (can be an Azure VM or a physical server) :
* One DC acting as ToR Router (router between SDN Stack and outside)
    * TOR router can be deployed to a dedicated VM and more DCs can be added (see Azure_E16_v3\SDNNested-Deploy-Infra.psd1 config file ) 
* Two Hypv HOSTs where SDN stack will be deployed (with SDNExpress script)
    * Could add more HYPV Hosts, just need to customize SDNNested-Deploy-Infra.psd1 config file
    * Cluster with S2D Disk pool is needed to manage SDN Stack with WAC)
        * Set SDNonS2D = $true into the SDNNested-Deploy-Infra.psd1 if you want to store VMs into the ClusterStorage (performance issue/penalty in a Nested env). By default, it is set to $false.
* Two Tenants "external" Gateways (Contoso GW will use L3 and Fabrikam IPSEC tunneling) to simulate remote tenant network connectivity with the SDN LAB
    *  Could add more or less Tenants, just need to customize SDNNested-Deploy-Tenant.psd1 or SDNNested-Deploy-Tenant-Container.psd1 config file 

On the SDN-HOSTs :
* A Network controller ServiceFabric Cluster (with minimum of 3 nodes ) or a standalone (see SDNExpress-Config.psd1) 
  * Only one node deployed by default
* Two multi-tenant Gateways
* Two MUXes
* Tenant VMs - based on the deployement config files used (see SDNNested-Deploy-Tenant.psd1 or SDNNested-Deploy-Tenant-Container.psd1 config files )
    * Tenant VM will run a IIS-Website, from the LocalMAchine browser reach http://VIP and the WebPage will shows to which tenant VM (DIP) the SLB has been delivred HTTP the request
    * Tenant ContainerHost's VM will run a IIS-Website container image, from the LocalMAchine browser reach http://VIP and the WebPage will indicate to which tenant VM (DIP) the SLB has been routed the HTTP request
    *   In the Container case, SLB is forwarding the packet to the ContainerHost Tenant VM (DIP), then inside the ContainerHost a second LB is configured to load-balanced to running containers.               

IP subnets and VLAN ID(can be changed):
- MGMT 10.184.108.0/24 - VLAN 7
- PROVIDER 10.10.56.0/23 - VLAN 11
- CONTOSO L3 INTERCO 10.127.134.0/25 - VLAN 1001
- INTERNET vSwitch 192.168.1.0/24 - VLAN 2
- CONTOSO and FABRIKAM SUBNET (voluntary the same to demonstrate isolation): 172.16.1.0/24 
    *  Contoso-testVM01 - 172.16.1.10/24
    *  Contoso-testVM02 - 172.16.1.11/24
    *  Fabrikam-testVM01 - 172.16.1.10/24
    *  Fabrikam-testVM02 - 172.16.1.11/24
- Public VIP which can be reached from AzVM 
    * 41.40.40.8 -> CONTOSO
    * 41.40.40.9 -> FABRIKAM
- Outbound NAT :
    * 41.40.40.18 -> CONTOSO
    * 41.40.40.19 -> FABRIKAM
- iDNS zones for Tenants :
    * VNET-Tenant-Fabrikam.sdn-cloud.net 
    * VNET-Tenant-Contoso.sdn-cloud.net
- All SDN VMs has Internet Access through Hypv NAT
- BGP peering towards external GW (FABRIKAM-GW01 and CONTOSO-GW01):
    * L3 netconnection (VLAN 1001) for CONTOSO 
    * IPSEC tunnel (VIP 41.40.40.1) for FABRIKAM
- Wireshark or another Net Analyzer can used on the Azure VM (or your main Hypv host) to sniff network inside the SDN stack (port mirroring - select vNIC *Mirror*)
    * That helps to visualize a little bit the traffic flow (encapsulation and so on).
    * Packets from Hypv -> VFP -> DIP / tenants VMs cannot be seen using this method.
- Management of SDN stack:
    * Windows Admin Center WAS can be  installed (https://localhost) or use the SDNNested Module
    
# Deployment / USAGE 
PREREQUISITES : You must have VHDX syspreded images located inside the folder where the VM will be stored 
Ex: F:\VMs\Template\

PS C:\Users\vidou> dir F:\VMs\Template\
Directory: F:\VMs\Template
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/18/2020   8:49 PM                SDNNested
-a----       12/22/2019   3:10 PM    14801698816 Win2019-Core-Container.vhdx
-a----         9/5/2019   7:58 PM     6815744000 Win2019-Core.vhdx
-a----        8/28/2019  11:07 AM    10171187200 Win2019-GUI.vhdx 

If you are going to deploy SDNNested LAB on a AzureVM, VHDX can be copied from the share to the VM automatically when deploying the AzureVM
see SDNNestedAzHost.psd1 config file :
    AZFileShare                 = "\\rgazfrancediag.file.core.windows.net\sndtemplate"
    AZFileUser                  = "Azure\rgazfrancediag"
    AZFilePwd                   = "PROVIDE THE PASSWORD"

## STEP 0 - If using Azure VM 
*   Deploy Azure VM (skip this step if you are not using Azure):
    *   Use New-SDNNestedAzHost.ps1 script, run it from a machine with access to your Azure Subscription. 
        *   Config file is .\configfiles\{Azure_E8_v3,Azure_E16_v3,Whatever}\SDNNestedAzHost.psd1 to define :
            *  Subscription, ResourceGroupName, VMName, VMSize, VM username and  Password, AzFileShare where VHDX and misc apps/tools can be located
    
    *  PS C:\Users\vidou\OneDrive - Microsoft\code\vidou83\SDNNested>.\New-SDNNestedAzHost.ps1 -ConfigurationDataFile .\configfiles\Azure_E8_v3\SDNNestedAzHost.psd1
        * AzFile share folder tree has to have the following Tree structure : 
            * \\AzFileShare\Template => contains sysprered vhdx (Names have to the one referenced in the config files).
            * \\AzFileShare\Apps => put what you want...
            *  Template folder will be replicated on the AzVM to F:\VMs, and Apps to C:\

##  STEP 1 - Deploy DCs, ToR Router, SDN HOSTs and Tenant External GWs
PREREQUISITES : You must have the SDNNested folder locacted on F:\VMs\Template (download it from this github repo and then uncompress it). 
ex : F:\VMs\Template\SDNNested => Go into that folder to execute scripts. 
INFO : This folder will be mapped (SMB Share) to the SDN HOSTs (to Drive Z:).

*   Use New-SDNNestedInfra.ps1 script, run it from the physical machine or the VM where you want to deploy SDNNested LAB. Config file is SDNNested-Deploy-Infra.psd1 and can be fully customized.
    *   PS F:\VMs\Template\SDNNested>.\New-SDNNestedInfra.ps1  -ConfigurationDataFile .\configfiles\Azure_E8_v3\SDNNested-Deploy-Infra.psd1    

## STEP 2 - Deploy SDNv2 Stack using SDNExpress scprit 
To get the latest SDNExpress script please check out:
see https://github.com/microsoft/SDN/tree/master/SDNExpress (slow ring) or https://github.com/microsoft/SDN/tree/master/SDNExpress (fast ring)

IMPORTANT : Please use the SDNEXpress copy located under SDNNested except if you really need to implement something missing. The reason is that the SDNExpress script has been slightly modified to allow deployement on FailoverCluster. 

The SDNExpress Script has to be executed from one of SDN-HOST* (not from a PS Session but through Hyper-V VM Console) :
*   Use SDNExpress script, the script should be located under Z:\SDNNested\SDNExpress (mapped from local machine) :
    * PS Z:\SDNNested\SDNEXpress>.\SDNExpress.ps1  -ConfigurationDataFile ..\configfiles\Azure_E8_v3\SDNExpress-Config.psd1        

## STEP 3 - Deploy Tenant environement
REMINDER: think to start the Tenant external GW before if you want BGP peering and GRE autoconfig performed. GW VMs had been stopped during the infra deployment to save memory.

*   Use Add-SDNNestedTenant.ps1 script, the script should be located on the SDN-HOST on Z:\SDNNested :
    *   Option 1, Deploy Tenant VMs :
        * PS Z:\SDNNested>.Add-SDNNestedTenant.ps1 -ConfigurationDataFile .\configfiles\SDNNested-Deploy-Tenant.psd1 
            * This script will deploy Contoso and Fabrikam Tenants with virtual gateways and VIP
                * Contoso Gw is using L3 interconnection
                * Fabrikam Gw is using GRE tunelling 
            * Public VIP which can be reached from LocalMachine, 
                * http://41.40.40.8 -> CONTOSO
                * https//41.40.40.9 -> FABRIK
 *   Option 2, Deploy Tenant Container HOST VMs :
        * PS Z:\SDNNested>.Add-SDNNestedTenant.ps1 -ConfigurationDataFile .\configfiles\SDNNested-Deploy-Tenant-Container.psd1 
            * This script will deploy Contoso and Fabrikam Container HOST VM with virtual gateways and VIP
                * Contoso Gw is using L3 interconnection
                * Fabrikam Gw is using GRE tunelling 
            * Public VIP which can be reached from LocalMachine, 
                * http://41.40.40.8 -> CONTOSO
                * https//41.40.40.9 -> FABRIK

## Miscs
On the Azure VM itself:
* WAC can be installed to manage S2D cluster and SDN stack
* Wireshark can be installed with PortMirroring (automatically configured vNIC named Mirror) in place to visualize most of the traffic on the SDN Stack (Non and encapsulated one - VxLAN and GRE for instance).
By default, WAC and Wireshark installer are located under C:\apps (get from the AzureFileShare see configFile)

# Contributing
Please reach vidou@microsoft.com for any feedback or question.

# GITHUB usage
Some people might be new to using Git and GitHub so here is a simple workflow to facilitite Pull Requests which can be reviewed and merged easily.

Create a forked copy of the SDNNested repo from https://github.com/ViDou83/SDNNested
Clone that copy to your local machine (git clone https://github.com/*GitUserName*/sdn.git)
Create a new branch on your local machine with a descriptive name to indicate the changes you will be making (git checkout -b DescriptiveName)
Update and commit docs (git add, git commit, git push) to generate a preview viewable via GitHub (e.g. https://github.com/<GitUserName/blob/DescriptiveBranchName/filename.md)
Iterate on this branch until satisfied
Create a Pull Request into the master branch from https://github.com/ViDou83/SDNNested (Select Pull requests, New pull request) and compare across forks
At this point, the PR will be reviewed and merged into the master branch by one of the Maintainers.

# License
