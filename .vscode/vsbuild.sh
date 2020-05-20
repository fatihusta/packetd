#!/bin/bash
##
## Build mfw admin UI
##
TARGET=$1

docker-compose -f build/docker-compose.build.yml up --exit-code-from dev --build dev
BUILD_ERR=$(echo $?)

if [ $BUILD_ERR -eq 0 ]; then
    ssh root@$TARGET "/etc/init.d/packetd stop"; 
    sleep 5
    scp ./cmd/packetd/packetd root@$TARGET:/usr/bin/; 
    ssh root@$TARGET "/etc/init.d/packetd start"
fi

