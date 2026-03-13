#!/usr/bin/env bash


cd "$(dirname "$0")"

os=$(uname)
dir="$(pwd)/binaries/$os"

deviceUDID = null
outputConsole = null

echo 'MiniKick working...'
echo $("$dir"/ideviceinfo | grep "$2: " | sed "s/$2: //")

killall iproxy

idevicepair pair

ideviceinfo > outputConsole

grabbedUDIDinfo=$(grep 'UniqueDeviceID:' outputConsole)

fixedUDID=${grabbedUDIDinfo/UniqueDeviceID: /}

echo 'Great success!'
echo 'Detected UDID: '$fixedUDID

./ideviceenterrecovery $fixedUDID
