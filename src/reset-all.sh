#!/bin/sh 
hbase shell <<EOF
disable "cif_objs"
drop "cif_objs"
create 'cif_objs', {NAME=>'cf', COMPRESSION=>'SNAPPY'}
EOF
./reset-index.sh
exit 0

