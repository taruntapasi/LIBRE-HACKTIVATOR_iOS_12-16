#!/usr/bin/env bash

echo ""
echo "
░░░░░░░░░░░░░░░░░░▄░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▌▄▄▄▀█▄░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░█░░░░██░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░█▄▄█▀▀░░░░░░░░░░░░░░░░
░░░░░░░░░░░░▄▄░░░░▌░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░██▀░░▀▀█▐░░░░▄▄▄░░░░░░░░░░░░░░░
░░░░░░░█░░░░░░░░░█▌░█░░░░▀█░░░░░░░░░░░░░
░░░░░░░▌░░░░░░░░░▐█▀░░░░░░░░█░░░░░░░░░░░
░░░░░░█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░▌░░░░░░░░░░░░░░░░░░░░░░▌░░░░░░░░░░
░░░░░░▌░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░
░░░░░░▌░░░░░░░░░░░░░░░░░░░░░░▐░░░░░░░░░░
░░░░░░▌░░░░░░░░░░░░░░░░░░░░░░▐░░░░░░░░░░
░░░░░░▌░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░
░░░░░░█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░▐░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░
░░░░░░░█▄░░░░░░░░░░░░░░░░░░░▌░░░░░░░░░░░
░░░░░░░░░▀▄▄░░░░░░▀█░░░░░░░█░░░░░░░░░░░░
░░░░░░░░░░░░▀▀▄▄▄▄▌▐▄▄▄▄▄█░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
"
echo ""


echo 'THIS MAY TAKE SOME TIME TO INSTALL. JUST WAIT...'
sleep 2
echo "Installing the Requiments..."
echo ''
echo ""
sudo apt update
sudo apt upgrade
sudo apt install -y libtool
echo ""
echo "Please Wait !"
sudo apt update
sleep 1
sudo add-apt-repository universe
sudo apt-get update
sudo apt install libimobiledevice-utils libusbmuxd-tools git curl python3 python3-pip -y
wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.16_amd64.deb
sudo apt-get update
echo ""
echo "Installing python..."
sudo apt install python3
sudo apt install irecovery
sudo apt install python3
pip3 install libimobiledevice
echo ""
echo ""
sudo apt install sshpass
python3 -m pip install --upgrade pip
sudo apt update
echo ""
sudo apt update
echo ""
echo ""
sudo apt upgrade
echo "Done!"
echo ""
echo "FINISHED INSTALLING REQUIMENTS!!!"
echo ""
echo "DONE!!"
echo ""
exit 1
