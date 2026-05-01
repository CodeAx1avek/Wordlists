subfinder -dL domain.txt -all -recursive -o subdomains.txt

cat subdomains.txt | httpx -silent -status-code -title -tech-detect -content-length -websocket -ip -csp-probe -tls-probe -p 80,443,8080,8443,8000,8888,9000,3000,5000,7000 -threads 200 -o alive.txt

cat alive.txt | awk '{print $1}' | sort -u > clean-urls.txt

katana -list clean-urls.txt -d 5 -silent -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

cat allurls.txt | grep -iE "/(backup|temp|tmp|log|cache|secret|private|conf|config|data|dump|export|archive|old|legacy|deprecated|test|dev|staging|qa|uat|internal|admin|git|svn)/|\.(env|key|pem|crt|secret|passwd|shadow|credentials|aws|git|svn|backup|bak|old|sql|dump|db|log|config|ini|conf|htaccess|htpasswd|zip|tar|gz|rar|7z|DS_Store)" | sort -u > sensitive-all.txt

# See what types of sensitive files
cat sensitive-files.txt | grep -oE '\.[a-z]+$' | sort | uniq -c | sort -rn

# See which subdomains have most sensitive files
cat sensitive-files.txt | awk -F/ '{print $3}' | sort | uniq -c | sort -rn | head -10

# Extract just the juicy ones (configs, keys, backups)
cat sensitive-files.txt | grep -iE "\.(env|key|pem|crt|secret|passwd|shadow|credentials|aws|git|backup|bak|old|sql|dump|db)" | tee juicy-files.txt
