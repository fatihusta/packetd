#!/bin/bash
##
## Build mfw admin UI
##
TARGET=$1

docker-compose -f build/docker-compose.build.yml up --exit-code-from musl --build musl
if [ $? -ne 0 ]
then 
    echo "Build failed, aborting"
    exit -1
fi
ssh root@$TARGET "/etc/init.d/packetd stop"; 
sleep 5
scp ./cmd/packetd/packetd root@$TARGET:/usr/bin/; 
scp ./cmd/packetd/packetd_rules root@$TARGET:/usr/bin;
ssh root@$TARGET "/etc/init.d/packetd start"

