# BEST OVERALL - Use this for everything
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -content-length -websocket -ip -csp-probe -tls-probe -p 80,443,8080,8443,8000,8888,9000,3000,5000,7000 -threads 200 -o alive.txt

# Why this is best:
# -silent       : No noise, only results
# -status-code  : Shows HTTP status (200,403,401,500)
# -title        : Page title (helps identify apps)
# -tech-detect  : Detects tech stack (nginx, react, wordpress)
# -content-length: Detects empty responses
# -websocket    : Checks WS/WSS support
# -ip           : Shows resolved IP
# -csp-probe    : Checks CSP headers for bypass
# -tls-probe    : Checks SSL/TLS info
# -p            : Multiple ports
# -threads 200  : Fast
