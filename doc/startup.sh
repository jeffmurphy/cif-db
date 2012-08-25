#!/bin/sh 

# if you are using cloudera
 /etc/init.d/hbase-thrift stop
 /etc/init.d/hbase-master stop
 /etc/init.d/hadoop-hdfs-datanode stop
 /etc/init.d/hadoop-hdfs-namenode stop
 
 /etc/init.d/hadoop-hdfs-datanode start
 /etc/init.d/hadoop-hdfs-namenode start

 sleep 5

 hdfs fsck /
 sudo -u hdfs hdfs dfsadmin -safemode leave
  
 /etc/init.d/hbase-master start
 /etc/init.d/hbase-thrift start


exit 0

# firsttime
sudo -u hdfs hdfs namenode -format
sudo -u hdfs hdfs dfs -mkdir /hbase
sudo -u hdfs hdfs dfs -chown hbase /hbase

# if you are using apache tarballs

   $HOME/src/hbase-0.92.1/bin/hbase-daemon.sh stop thrift
   $HOME/src/hbase-0.92.1/bin/stop-hbase.sh 
   $HOME/src/hadoop-1.0.3/bin/stop-all.sh 
   $HOME/src/hadoop-1.0.3/bin/start-all.sh 
   $HOME/src/hadoop-1.0.3/bin/hadoop dfsadmin -safemode leave
   $HOME/src/hadoop-1.0.3/bin/hadoop fsck /
   $HOME/src/hbase-0.92.1/bin/start-hbase.sh 
   $HOME/src/hbase-0.92.1/bin/hbase-daemon.sh start thrift

