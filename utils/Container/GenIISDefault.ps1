$colors = @("red", "blue", "green", "yellow", "purple", "orange", "pink", "gray" )
$index = Get-Random -Minimum 0 -Maximum 8
$IP=(Get-NetAdapter | Get-NetIPAddress | ? AddressFamily -eq IPv4).IPAddress

mv C:\inetpub\wwwroot\iisstart.htm C:\inetpub\wwwroot\iisstart.htm.old -Force
$background = $colors[$index]
$content = @"
<html>
<body bgcolor="$background">
<h1>ContainerHost=$env:CONTAINER_HOST</h1>
<h1>ContainerId=$env:computername</h1>
<h1>ContainerIp=$IP</h1>
</body>
</html>
"@
Add-Content -Path C:\inetpub\wwwroot\iisstart.htm $content

while(1){sleep 1}