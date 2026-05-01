subfinder -dL domain.txt -all -recursive -o subdomains.txt

cat subdomains.txt | httpx -silent -status-code -title -tech-detect -content-length -websocket -ip -csp-probe -tls-probe -p 80,443,8080,8443,8000,8888,9000,3000,5000,7000 -threads 200 -o alive.txt

