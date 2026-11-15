Get-VM | Where-Object { $_.Name -like 'icss-*' } | Stop-VM -Force -ErrorAction SilentlyContinue
Get-VM | Where-Object { $_.Name -like 'icss-*' } | Remove-VM -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\VMs\ICSS-Cluster' -Directory -Filter 'icss-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-VM | Select-Object Name, State | Format-Table -AutoSize
Write-Host "Cleanup done."