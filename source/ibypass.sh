#!/bin/bash

echo "Welcome to iCloud Unlock  0.1"
echo "To make this exploit work, we will launch checkra1n jailbreak. Please follow the instructions and do not close the terminal."
echo "If you want to exit the script, press Ctrl+C."
read -p "Press enter to continue"

echo "Checking for python3..."
if ! command -v python3 &> /dev/null; then
  echo 'Error: python3 is not installed.' >&2
  exit 1
else
  echo "python3 is installed"
fi

echo "Checking for pip3..."
if ! command -v pip3 &> /dev/null; then
  echo 'Error: pip3 is not installed.' >&2
  exit 1
else
  echo "pip3 is installed"
fi

sudo ./source/exe/jk

while true; do
  read -p "Is the jailbreak done? (y/n): " yn
  case $yn in
    [Yy]* )
      break;;
    [Nn]* )
      echo "Please wait for the jailbreak to complete. Press Ctrl+C to exit if needed."
      sleep 10;;
    * )
      echo "Please answer y or n.";;
  esac
done

for script in "./source/scripts/bypass.py" "./source/scripts/usbmux.py"; do
  if [ -f "$script" ]; then
    echo "$script found"
  else
    echo "$script not found"
    exit 1
  fi
done

echo "Installing required libs..."
sudo pip3 install paramiko

echo "All files are found"
echo "Good luck"

echo "Starting python scripts..."
echo "Let the script finish. Wait 2-5 minutes, and your device should be unlocked."
echo "ON COMPLETE REBOOT DEVICE MAY BE LOCKED, AND SIM CARD WON'T WORK"
echo "ON SOME IOS VERSIONS THIS WON'T WORK. PLEASE DO NOT UPDATE; IF IT DOES NOT WORK, DOWNGRADE IOS"

for i in {1..5}; do
  echo "Starting at $i"
  sleep 1
done

python3 ./source/scripts/bypass.py

exit 0
