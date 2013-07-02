#!/bin/sh -x

# botnet, fastflux, malware, nameserver, phishing, scan, spamvertising, suspicious, whitelist

hbase shell <<EOF
disable "index_exploit"
disable "index_malware"
disable "index_spam"
disable "index_suspicious"
disable "index_botnet"
disable "index_fastflux"
disable "index_nameserver"
disable "index_phishing"
disable "index_scan"
disable "index_spamvertising"
disable "index_whitelist"
drop "index_exploit"
drop "index_malware"
drop "index_spam"
drop "index_suspicious"
drop "index_botnet"
drop "index_fastflux"
drop "index_nameserver"
drop "index_phishing"
drop "index_scan"
drop "index_spamvertising"
drop "index_whitelist"
put 'registry', 'exploder.checkpoint.0', 'b:value', '0'
EOF

exit 0
