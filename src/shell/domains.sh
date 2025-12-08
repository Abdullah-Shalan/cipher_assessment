# !/bin/bash

WEB_LOG="../web_access.log"
BENIGN="../benign_domains.txt"

awk -F\" '{print $4}' "$WEB_LOG" > all_domains.txt
total_domains=$(cat all_domains.txt | wc -l)

sort all_domains.txt -uo all_domains.txt
sort "$BENIGN" -uo benign_sorted.txt 

unique_domains=$(cat all_domains.txt | wc -l)

# fetch domains not in benign, and unique to web_access.log 
comm all_domains.txt benign_sorted.txt -32 > sus_domains.txt
sus_count=$(cat sus_domains.txt | wc -l)

# fetch benign domains found in web_access.log
comm all_domains.txt benign_sorted.txt -12 > benign_found.txt
benign_count=$(cat benign_found.txt | wc -l)

echo "= Summary Report =" > report.txt
echo "- Total log entries processed : $total_domains" >> report.txt
echo "- Unique domains found : $unique_domains" >> report.txt

echo "= Suspicious Domains =" >> report.txt
cat sus_domains.txt >> report.txt
echo "- Suspicious domains count : $sus_count" >> report.txt

echo "= Benign Domains =" >> report.txt
cat benign_found.txt >> report.txt
echo "- Benign domains identified count : $benign_count" >> report.txt

rm all_domains.txt benign_found.txt benign_sorted.txt sus_domains.txt