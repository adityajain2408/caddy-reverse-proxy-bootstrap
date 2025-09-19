# caddy-reverse-proxy-bootstrap
PowerShell script to install Caddy on a windows machine and create a reverse proxy of http://127.0.0.1:9000. This script can be used to talk to Tally from a https browser service worker request.  

Optional: skip installer if you already have caddy.exe
If you can manually place caddy.exe at C:\ProgramData\TallyHttpsProxy\caddy.exe as well if you face anhy download and extraction issues,and the script jumps straight to service setup. 

# how to run
Run the script as Administrator permissions in PowerShell:
powershell -ExecutionPolicy Bypass -File .\static\tools\tally-proxy-bootstrap.ps1

If it sits at “Downloading: …” for more than ~3 minutes, cancel and try this quick network test:

curl.exe -I --max-time 20 https://github.com/caddyserver/caddy/releases/latest/download/caddy_windows_amd64.zip

If that times out, you have a network/proxy issue.
