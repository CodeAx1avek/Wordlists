subfinder -dL domain.txt -all -recursive -o subdomains.txt

cat subdomains.txt | httpx -silent -status-code -title -tech-detect -content-length -websocket -ip -csp-probe -tls-probe -p 80,443,8080,8443,8000,8888,9000,3000,5000,7000 -threads 200 -o alive.txt

cat alive.txt | awk '{print $1}' | sort -u > clean-urls.txt

gau --subs --providers wayback,alienvault,commoncrawl,otx,urlscan --threads 50 --timeout 5 --retry 2 < clean-urls.txt | katana -silent -f smart -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
