# LIBRE-HACKTIVATOR 12-16

`LIBRE-HACKTIVATOR 12-16` is an iCloud/Activation Lock bypass toolkit for checkm8-capable iOS devices, built around shell and python scripts, and bundled palera1n assets.

## Legal Disclaimer

Use this only on devices you own or are explicitly authorized to service. Unauthorized use may violate law, policy, or terms of service. This repo is provided as-is with no warranty; you accept all risk.

## What This Repository Is

- A menu launcher: `start.sh`
- iOS 12-14 helper flows in `source/` (Python + shell)
- iOS 15-16.x flows built around `palera1n/palera1n.sh`
- OS-specific helper scripts and binaries in `device/Darwin` and `device/Linux`

It is script-driven, not packaged software.

## Platform Support

- Host OS: macOS (`Darwin`) and Linux
- Windows: not supported by `start.sh`

## How To Run

From repo root:

```bash
bash ./start.sh
```

`start.sh` is the main entrypoint and presents a 1-13 menu.

## Menu Map (Exact Behavior)

1. `source/ibypass.sh`
   Verifies `python3` and `pip3`, runs `sudo ./source/exe/jk`, waits for you to confirm jailbreak is done, installs `paramiko`, then starts `source/scripts/bypass.py`. That script relays `localhost:2222 -> device:44` and runs:
   `mount -o rw,union,update /; cd /Applications; mv Setup.app Setup.app.bak; uicache -a; killall -9 SpringBoard`.
2. `source/php.sh`
   Verifies `python3` and `pip3`, installs `paramiko`, runs `python3 ./source/scripts/php.py restore` to push `RaptorActivation.pem` over SFTP, then runs `source/scripts/phpbypass/start.sh` to start the local PHP activation flow and call `ideviceactivation`.
3. `source/rm_oldicloud.sh`
   Verifies `python3` and `pip3`, installs `paramiko`, then runs `remove_oldicloud.py`. It connects over SSH relay and runs:
   `cd /var/mobile/Library; rm -r Accounts; mkdir Accounts;`
   It also appends `FactoryActivated` to `com.apple.mobile.lockdown_cache-ActivationState`.
4. `source/root_shell.sh`
   Verifies `python3` and `pip3`, installs `paramiko`, and runs `shell.py`, which opens an interactive shell and sends each command over SSH (`root/alpine` through `localhost:2222`).
5. `source/simfrom.sh`
   Verifies `python3` and `pip3`, installs `paramiko`, then runs `python3 ./source/scripts/sim.py restore`.
6. `source/simto.sh`
   Verifies `python3` and `pip3`, installs `paramiko`, then runs `python3 ./source/scripts/sim.py restore` (same command as option 5).
7. `palera1n/palera1n.sh -cf`
   Runs `palera1n` with `-cf`.
8. `palera1n/palera1n.sh -f`
   Runs `palera1n` with `-f`.
9. `device/<OS>/bypass.sh`
   Clears `~/.ssh/known_hosts`, starts `iproxy 4444:44`, fetches `patch` and `com.bypass.mobileactivationd.plist`, remounts `/` as read-write, replaces `/usr/libexec/mobileactivationd`, loads the launch daemon, and triggers `launchctl reboot userspace`.
10. `device/<OS>/enterrecovery.sh`
   Pairs the device, reads the UDID from `ideviceinfo`, then runs `./ideviceenterrecovery <UDID>`.
11. `device/<OS>/exitrecovery.sh`
   Runs `./irecovery -n`.
12. `install.sh`
   Linux apt-based installer: runs several `apt update/upgrade` steps, installs `libimobiledevice` tools, fetches and installs a `libssl1.1` `.deb`, installs `sshpass`, upgrades pip, and exits with status `1`.
13. Exit

## Dependencies (From Scripts)

Common across flows:

- `bash`
- `python3`
- `pip3`
- Python package: `paramiko`
- USB/iOS tools used across scripts:
  - `ideviceinfo`
  - `ideviceenterrecovery`
  - `iproxy`
  - `irecovery`
  - `sshpass`

Additional dependencies referenced:

- `php` (PHP bypass server flow)
- `screen` (PHP bypass server flow)
- `ideviceactivation` (PHP bypass activation call)
- For `palera1n/palera1n.sh`: `curl`, `unzip`, `git`, `ssh`, `scp`, `killall`, `sudo`, `grep`, `pgrep` (and `lsusb` on Linux), plus `pyimg4` (auto-installed if missing)

`install.sh` is Linux/apt-oriented and runs multiple `sudo apt` operations.

## Repository Layout

```text
.
├── .gitignore
├── README.md
├── start.sh
├── install.sh
├── source/
│   ├── ibypass.sh
│   ├── jailbreak.sh
│   ├── php.sh
│   ├── rm_oldicloud.sh
│   ├── root_shell.sh
│   ├── simfrom.sh
│   ├── simto.sh
│   ├── exe/
│   │   └── .gitkeep
│   └── scripts/
│       ├── bypass.py
│       ├── php.py
│       ├── remove_oldicloud.py
│       ├── shell.py
│       ├── sim.py
│       ├── usbmux.py
│       └── phpbypass/
│           ├── start.sh
│           ├── activator.php
│           ├── raptor/RaptorActivation.pem
│           └── var/www/crypt/{BigInteger.php,Hash.php,Random.php,RSA.php}
├── device/
│   ├── Darwin/
│   │   ├── bypass.sh
│   │   ├── enterrecovery.sh
│   │   ├── exitrecovery.sh
│   │   └── {ideviceenterrecovery,ideviceinfo,iproxy,irecovery,sshpass,outputConsole}
│   └── Linux/
│       ├── bypass.sh
│       ├── enterrecovery.sh
│       ├── exitrecovery.sh
│       └── {ideviceenterrecovery,ideviceinfo,iproxy,irecovery,sshpass,outputConsole}
└── palera1n/
    ├── palera1n.sh
    ├── binaries/
    │   ├── kpf.ios
    │   ├── Darwin/ {Kernel64Patcher,iBoot64Patcher,iBootpatch2,idevice*,img4,iproxy,irecovery,jq,pzb,sshpass}
    │   └── Linux/  {Kernel64Patcher,iBoot64Patcher,iBootpatch2,idevice*,img4,iproxy,irecovery,jq,pzb,sshpass}
    ├── other/
    │   ├── bootlogo.im4p
    │   ├── payload/{payload_t8010.bin,payload_t8015.bin}
    │   └── rootfs/jbin/post.sh
    └── ramdisk/
        ├── sshrd.sh
        ├── Darwin/ (tool binaries)
        ├── Linux/ (tool binaries)
        ├── shsh/{0x7000,0x7001,0x8000,0x8001,0x8003,0x8010,0x8011,0x8012,0x8015,0x8960}.shsh
        └── other/{bootlogo.im4p,ramdisk.tar.gz}
```

## Behavior Notes Per Flow

- `source/*.sh` wrappers usually:
  - verify `python3`/`pip3`
  - run `sudo pip3 install paramiko`
  - execute a script in `source/scripts/`
- Python helpers (`bypass.py`, `php.py`, `remove_oldicloud.py`, `shell.py`, `sim.py`) use `usbmux.py` + `paramiko` to connect to device services on port `44` and bridge to local `2222`.
- `device/*/bypass.sh` starts local `iproxy 4444:44` and pushes a remote patch/plist to the device.
- `palera1n/palera1n.sh` is the largest flow and includes ramdisk creation/boot steps, patching operations, and network fetches from multiple external endpoints.

## Safety Recommendations

- Back up device data before running any flow.
- Connect only one iOS device at a time.
- Use reliable USB cable/port and avoid hub instability.
- Read script contents before execution and adapt for your environment.
