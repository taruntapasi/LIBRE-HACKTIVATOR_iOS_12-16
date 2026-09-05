#!/usr/bin/env bash
set -uo pipefail

print_banner() {
  cat <<'EOF'

░░░░░░░░░░░░░░░░░░▄░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▌▄▄▄▀█▄░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░█░░░░██░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░█▄▄█▀▀░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░▌░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░██▀░░▀▀█▐░░░░▄▄▄░░░░░░░░░░░░░░░
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
EOF
}

run_as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "Root or sudo access is required for package installation; skipping package setup." >&2
    return 1
  fi
}

main() {
  print_banner
  echo 'THIS MAY TAKE SOME TIME TO INSTALL. JUST WAIT...'
  echo "Installing the required dependencies..."

  if command -v apt-get >/dev/null 2>&1; then
    if ! run_as_root apt-get update; then
      echo "Package manager update failed; continuing without package installation." >&2
    fi

    if ! run_as_root apt-get install -y --no-install-recommends libtool libimobiledevice-utils libusbmuxd-tools git curl python3 python3-pip sshpass 2>/dev/null; then
      echo "Some packages were not installed; continuing with the available tools." >&2
    fi

    if command -v add-apt-repository >/dev/null 2>&1; then
      run_as_root add-apt-repository universe >/dev/null 2>&1 || true
    fi

    if ! run_as_root apt-get update >/dev/null 2>&1; then
      echo "apt-get update failed after installation; package setup is incomplete." >&2
    fi

    if command -v apt-cache >/dev/null 2>&1 && apt-cache policy libssl1.1 >/dev/null 2>&1; then
      run_as_root apt-get install -y --no-install-recommends libssl1.1 || true
    else
      echo "libssl1.1 is not available on this distro; skipping the legacy OpenSSL package." >&2
    fi

    if command -v python3 >/dev/null 2>&1; then
      python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
      python3 -m pip install libimobiledevice >/dev/null 2>&1 || true
    fi
  else
    echo "No supported package manager was found. Skipping dependency installation for this environment." >&2
  fi

  echo "Done!"
  echo "FINISHED INSTALLING REQUIREMENTS!!!"
  echo "DONE!!"
  return 0
}

main "$@"
exit $?
