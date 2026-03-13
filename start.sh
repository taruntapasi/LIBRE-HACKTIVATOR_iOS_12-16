#!/usr/bin/env bash

cd "$(dirname "$0")" || exit 1

get_device_dir() {
  case "$(uname)" in
    Darwin) echo "./device/Darwin" ;;
    Linux) echo "./device/Linux" ;;
    *)
      echo "Unsupported OS: $(uname). Use macOS (Darwin) or Linux." >&2
      return 1
      ;;
  esac
}

run_device_script() {
  local script_name="$1"
  local device_dir

  device_dir="$(get_device_dir)" || return 1

  if [ ! -f "$device_dir/$script_name" ]; then
    echo "Missing script: $device_dir/$script_name"
    return 1
  fi

  bash "$device_dir/$script_name"
}

print_overview() {
  cat <<'EOF'
============================================================
Overview of LIBRE-HACKTIVATOR 12-16
============================================================
My Names i3t4an, I used to do a lot more Icloud bypass work
back in the day just because I liked the challenge. I have
since moved on to other things. I decided I would open source
the tool kit I used for Checkm8 devices for iOS 12-16. I 
believe in open source, FREE AS IN FREEDOM.


============================================================
EOF
}

while true; do
  echo
  print_overview
  echo
  echo "Unified tool kit Menu"
  echo "1) iOS 12-14 iCloud bypass"
  echo "2) iOS 12-14 PHP bypass"
  echo "3) iOS 12-14 remove old iCloud"
  echo "4) iOS 12-14 root shell"
  echo "5) iOS 12-14 SIM dump from device"
  echo "6) iOS 12-14 SIM restore to device"
  echo "7) iOS 15-16 build fakefs"
  echo "8) iOS 15-16 boot fakefs"
  echo "9) iOS 15-16 bypass"
  echo "10) Enter recovery mode"
  echo "11) Exit recovery mode"
  echo "12) Install dependencies"
  echo "13) Exit"
  read -r -p "Select an option [1-13]: " choice

  case "$choice" in
    1) bash ./source/ibypass.sh ;;
    2) bash ./source/php.sh ;;
    3) bash ./source/rm_oldicloud.sh ;;
    4) bash ./source/root_shell.sh ;;
    5) bash ./source/simfrom.sh ;;
    6) bash ./source/simto.sh ;;
    7) bash ./palera1n/palera1n.sh -cf ;;
    8) bash ./palera1n/palera1n.sh -f ;;
    9) run_device_script "bypass.sh" ;;
    10) run_device_script "enterrecovery.sh" ;;
    11) run_device_script "exitrecovery.sh" ;;
    12) bash ./install.sh ;;
    13) echo "Bye."; exit 0 ;;
    *) echo "Invalid option. Pick 1-13." ;;
  esac
done
