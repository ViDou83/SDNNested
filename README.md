# SDNNested
SDNNested is a collection of PS Script that automates the Microsoft SDN deployment on a Azure VM Nested Environement.

## Infrastucture deployed with provided config files
Azure VM acting as Hypv Server (1st level of Nested virtualization )
* One DC + one ToR Router
* Two Hypv host where SDN stack will be deployed (with SDN Express script)
* Two tenants "physical" Gateway (Tenants Contoso L3 and Fabrikam GRE tunnem)

On SDN-HOST Hypv Server (2nd level of Nested virtualization ):
* One Network controller Cluster composed of 3 nodes
* Two Gateways + Tenants vGW (L3 + GRE)
* Two MUXes
* Two Contoso Tenant VMs
* Two Fabrikam Tenant VMs

## Usage


## Contributing

## License
