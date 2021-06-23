
import-module c:\temp\HNS.V2.psm1

$VIP=(Get-NetIPAddress -AddressFamily IPv4 | ? IPAddress -Match "172.16.1.").IPAddress
$endpoints = Get-HnsEndpoint

Write-Host -ForegroundColor Green "Creating LoadBalancer on Container Host using HNVv2 API "
New-HnsLoadBalancer -InternalPort 80 -ExternalPort 80 -Endpoints $endpoints.Id -Protocol 6 -Vip $VIP -DSR