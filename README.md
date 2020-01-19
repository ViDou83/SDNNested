# Deploy Microsoft SDNv2 2019 on one single machine 
SDNNested is a collection of PSScript that automates the deployment of a Microsoft SDNv2 LAB on a Nested Environement. 
That can be executed either on a physical machine or a VM. HYPV role is required (Nested Virtualization will be use). 
https://docs.microsoft.com/en-us/windows-server/networking/sdn/software-defined-networking

## Example of deployed infrastucture

Please examine and understand config files structure before running deployement. You can either use provided config files or simply copy one folder and rename it based on your need.

VM acting as Hypv Server (can be a Azure VM) :
* One DC acting as ToR Router (router between SDN Stack and outside)
    * TOR router can be deployed to a dedicated VM and mode DCs can be added (see SDNNested-Deploy-Infra.psd1 config file ) 
* Two Hypv host (Cluster with S2D Disk pool - needed to manage SDN Stack with WAC) where SDN stack will be deployed (with SDNExpress script)
    * Could add more, just need to customized SDNNested-Deploy-Infra.psd1 config file 
* Two tenants "physical" Gateway (Tenants Contoso L3 and Fabrikam GRE tunnel) to simulate remote tenant network (outside the SDN Stack)
    *  Could add more or less, just need to customized SDNNested-Deploy-Tenant.psd1 or SDNNested-Deploy-Tenant-Container.psd1 config file 

On the SDN-HOSTs Hypv Server cluster :
* One Network controller Cluster or a standalone (see SDNExpress-Config.psd1) 
* Two Gateways (see SDNExpress-Config.psd1) 
* Two MUXes (see SDNExpress-Config.psd1) 
* Tenant VMs based on the deployement (see SDNNested-Deploy-Tenant.psd1 or SDNNested-Deploy-Tenant-Container.psd1 config files )
    * Tenant VM will run a IIS-Website to allow visualize from the browser where the SLB is delivering the request
    * Tenant ContainerHost VM will run a IIS-Website container image to allow visualize from the browser where the SLB is delivering the request. SLB is delivring the packet to the primary IPaddr of the ContainerHOST VM, then inside the ContainerHost a second LB is configured.               

IP subnets and VLAN (can be changed):
- MGMT 10.184.108.0/24 - VLAN 7
- PROVIDER 10.10.56.0/23 - VLAN 11
- CONTOSO L3 INTERCO 10.127.134.0/25 - VLAN 1001
- CONTOSO and FABRIKAM SUBNET (voluntary the same to demonstrate isolation): 172.16.1.0/24 
    *  Contoso-testVM01 - 172.16.1.10/24
    *  Contoso-testVM02 - 172.16.1.10/24
    *  Fabrikam-testVM01 - 172.16.1.10/24
    *  Fabrikam-testVM02 - 172.16.1.10/24
- Public VIP which can be reached from AzVM 
    * 41.40.40.8 -> CONTOSO
    * 41.40.40.9 -> FABRIKAM

### Azure VM case
On the Azure VM itself:
* WAC can be installed to manage S2D cluster and SDN stack
* Wireshark can be installed with PortMirroring (automatically configured vNIC named Mirror) in place to visualize most of the traffic on the SDN Stack (Non and encapsulated one - VxLAN and GRE for instance).
By default, WAC and Wireshark installer are located under C:\apps (get from the AzureFileShare see configFile)

![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/diagram.jpg?raw=true)
![image](https://github.com/ViDou83/SDNNested/blob/master/utils/pictures/legende.jpg?raw=true)


## Usage

### If using Azure VM 
*   Deploy Azure VM (skip this step if you are not using Azure):
    *   Use New-SDNNestedAzHost.ps1 script, run it from a machine with access to your Azure Subscription. Config file is SDNNestedAzHost.psd1 to define :
        *   Subscription, ResourceGroupName, VMName, VMSize, VM username and  Password, AzFileShare where VHDX and misc apps/tools can be hosted
        *  Ex: .\New-SDNNestedAzHost.ps1 -ConfigurationDataFile .\configfiles\Azure_E8_v3\SDNNestedAzHost.psd1
        * AzFile share folder tree has to be 
            * \\AzFileShare\Template => contains sysprered vhdx (Name has to the one used).
            * \\AzFileShare\Apps => put what you want...
            *  Template folder will be replicated on the AzVM F:\VMs Drive and App under C:\

### Deploy DCs, ToR Router, SDN HOSTs and Tenant External GWs
Deploy 1st level of Nested virtualization :
    *   Use New-SDNNestedInfra.ps1 script, run it from the Azure VM itself. Config file is SDNNested-Deploy-Infra.psd1 and can be fully customized. PREREQUISITES : You need to have VHDX generelazied hosted on the AzureVM. 
*   2nd level of Nested virtualization 
    *   Use SDNExpress script, please copy to one of SDN-HOST VM and run it locally from this host (not from a PS Session but through VM Console). You can use either the one located here, you can get the latest one from :
        https://github.com/grcusanz/SDN/tree/master/SDNExpress/scripts (not stable)
        https://github.com/microsoft/SDN/tree/master/SDNExpress/scripts(stable but not compatible with S2D)

    * Use script Add-SDNNestedTenant.ps1 script to use tenant on the SDN stack:
        * Ex: Add-SDNNestedTenant.ps1 -ConfigurationDataFile .\configfiles\SDNNested-Deploy-Tenant.psd1 
        * This script will deploy Contoso and Fabrikam Tenants with virtual gateways and VIP
            * Contoso Gw is using L3 interconnection
            * Fabrikam Gw is using GRE tunelling 
        * Public VIP which can be reached from AzVM, 
            * http://41.40.40.8 -> CONTOSO
            * https//41.40.40.9 -> FABRIK

## Contributing
Please reach vidou@microsoft.com for any feedback or question.

Some people might be new to using Git and GitHub so here is a simple workflow to facilitite Pull Requests which can be reviewed and merged easily.

Create a forked copy of the SDNNested repo from https://github.com/ViDou83/SDNNested
Clone that copy to your local machine (git clone https://github.com/*GitUserName*/sdn.git)
Create a new branch on your local machine with a descriptive name to indicate the changes you will be making (git checkout -b DescriptiveName)
Update and commit docs (git add, git commit, git push) to generate a preview viewable via GitHub (e.g. https://github.com/<GitUserName/blob/DescriptiveBranchName/filename.md)
Iterate on this branch until satisfied
Create a Pull Request into the master branch from https://github.com/ViDou83/SDNNested (Select Pull requests, New pull request) and compare across forks
At this point, the PR will be reviewed and merged into the master branch by one of the Maintainers.

## License
