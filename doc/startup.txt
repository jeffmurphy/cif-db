   src/hbase-0.92.1/bin/hbase-daemon.sh stop thrift
   src/hbase-0.92.1/bin/stop-hbase.sh 
   src/hadoop-1.0.3/bin/stop-all.sh 
   src/hadoop-1.0.3/bin/start-all.sh 
   $HOME/src/hadoop-1.0.3/bin/hadoop dfsadmin -safemode leave
   $HOME/src/hadoop-1.0.3/bin/hadoop fsck /
   src/hbase-0.92.1/bin/start-hbase.sh 
   src/hbase-0.92.1/bin/hbase-daemon.sh start thrift