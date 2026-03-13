#!/bin/bash

rm -rf ~/.ssh/known_hosts

cd "$(dirname "$0")" || exit

sleep 1

echo 'Start iproxy'
./iproxy 4444:44 > /dev/null 2>&1 &

echo -e "\nICLOUD BYPASS starting\n"

download_file() {
    local url="$1"
    local target_dir="$2"
    local file_name="$3"

    if curl -o "${target_dir}/${file_name}" "${url}"; then
        echo "${file_name} downloaded."
    else
        echo "${file_name} could not be downloaded."
        exit 1
    fi
}

download_file "https://applera1n.github.io/palera1n_files/patch" "./" "patch3"
download_file "https://applera1n.github.io/com.bypass.mobileactivationd.plist" "./" "com.bypass.mobileactivationd.plist"

echo "Mounting"
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'mount -o rw,union,update /'
echo "Mounted!"

./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'mv -v /usr/libexec/mobileactivationd /usr/libexec/mobileactivationdBackup'
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'ldid -e /usr/libexec/mobileactivationdBackup > /usr/libexec/mobileactivationd.plist'
./sshpass -p 'alpine' scp -rP 4444 -o StrictHostKeyChecking=no ./patch3 root@localhost:/usr/libexec/mobileactivationd
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'chmod 755 /usr/libexec/mobileactivationd'
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'ldid -S/usr/libexec/mobileactivationd.plist /usr/libexec/mobileactivationd'
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'rm -v /usr/libexec/mobileactivationd.plist'

./sshpass -p 'alpine' scp -rP 4444 -o StrictHostKeyChecking=no ./com.bypass.mobileactivationd.plist root@localhost:/Library/LaunchDaemons/com.bypass.mobileactivationd.plist
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'launchctl load /Library/LaunchDaemons/com.bypass.mobileactivationd.plist'
./sshpass -p 'alpine' ssh -o StrictHostKeyChecking=no -p 4444 "root@localhost" 'launchctl reboot userspace'

echo -e "\nICLOUD BYPASS done\n"

rm -rf ./patch3
rm -rf ./com.bypass.mobileactivationd.plist


echo 'Done'



        
        

