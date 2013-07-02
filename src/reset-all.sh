#!/bin/sh 
./reset-index.sh
hbase shell <<EOF
disable "cif_objs"
drop "cif_objs"
create 'cif_objs', {NAME=>'cf', COMPRESSION=>'SNAPPY'}
EOF
exit 0

