#!/usr/bin/env bash
set -euo pipefail

# === HamVOIP / Arch ARM WireGuard Auto-Setup (IPv4-only + optional IPTABLES firewall lockdown) ===
# This variant uses iptables (NOT nftables) to avoid wg-quick+nft syntax issues on older HamVOIP builds.
#
# Firewall lockdown (optional) - now includes:
#   - Suggested/templated service port sets (AllStar/EchoLink/HTTP/HTTPS/etc.)
#   - Optional user-defined extra ports (tcp/udp + single ports or ranges)
#
# IMPORTANT: If you are currently SSH'd in from a public IP, enabling the firewall will lock you out.
# Updated to add MTU 1380 as required by the new 44Net Connect Portal
#
# CHANGE: Allow HTTP port 80 inbound from RFC1918 LAN ranges (10/8, 172.16/12, 192.168/16)
#                while keeping port 80 blocked from the public internet.
#
# NEW (DROP-IN): Ensure iptables rules persist across reboots:
#   - Save to /etc/iptables/iptables.rules
#   - Enable iptables.service if present
#   - Otherwise install + enable iptables-restore@iptables.service

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Elevating with sudo..."
    exec sudo -E bash "$0" "$@"
  fi
}

ask_yes_no() {
  local prompt="$1" default="${2:-Y}" reply hint="[Y/n]"
  [[ "$default" =~ ^[Nn]$ ]] && hint="[y/N]"
  read -rp "$prompt $hint " reply || true
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]$ ]]
}

msg() { echo -e "\n==== $* ====\n"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing: $1"; exit 1; }; }

is_arch_like() {
  [[ -f /etc/os-release ]] || return 1
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "arch" || "${ID_LIKE:-}" == *arch* || "${NAME:-}" == *"Arch"* || "${NAME:-}" == *"HamVOIP"* ]]
}

list_module_dirs() { find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf "%f\n" 2>/dev/null | sort -V || true; }
latest_module_dir() { list_module_dirs | tail -n 1; }
running_kernel() { uname -r; }
kernel_modules_ok() { [[ -d "/lib/modules/$(running_kernel)" ]]; }

show_kernel_summary() {
  local run latest
  run="$(running_kernel)"
  latest="$(latest_module_dir)"
  echo "Running kernel:  ${run}"
  echo "Newest modules:  ${latest:-<none>}"
  echo "Modules present for running kernel? $([[ -d /lib/modules/$run ]] && echo YES || echo NO)"
  echo "Installed module dirs:"
  list_module_dirs | sed 's/^/  - /'
}

kernel_pkg_name_guess() {
  cat <<'EOF'
linux
linux-raspberrypi
linux-rpi
linux-aarch64
linux-headers
linux-raspberrypi-headers
raspberrypi-bootloader
raspberrypi-firmware
hamvoip-wireguard
hamvoip
hamvoip-base
hamvoip-kernel
EOF
}

updates_requiring_reboot() {
  local updates names line
  updates="$(pacman -Qu 2>/dev/null || true)"
  [[ -n "$updates" ]] || return 1
  names=" "
  while IFS= read -r line; do names+="${line%% *} "; done <<< "$updates"
  while IFS= read -r kpkg; do
    [[ -z "$kpkg" ]] && continue
    [[ "$names" == *" ${kpkg} "* ]] && return 0
  done < <(kernel_pkg_name_guess)
  [[ "$names" == *" linux"* || "$names" == *" raspberrypi"* ]] && return 0
  return 1
}

do_pacman_refresh() { msg "Refreshing package databases (pacman -Sy)"; pacman -Sy --noconfirm; }
do_pacman_upgrade() { msg "Upgrading packages (pacman -Su)"; pacman -Su --noconfirm; }

pkg_installed() { pacman -Q "$1" >/dev/null 2>&1; }
pkg_available() { pacman -Si "$1" >/dev/null 2>&1; }

install_wireguard_packages() {
  if pkg_available hamvoip-wireguard; then
    msg "HamVOIP WireGuard bundle detected (hamvoip-wireguard). Installing bundle and avoiding wireguard-tools conflict."
    if pkg_installed wireguard-tools; then
      echo "wireguard-tools is installed and conflicts with hamvoip-wireguard."
      if ask_yes_no "Remove wireguard-tools and install hamvoip-wireguard instead?" "Y"; then
        pacman -Rns --noconfirm wireguard-tools
      else
        echo "Aborting."
        exit 1
      fi
    fi
    pacman -S --noconfirm --needed hamvoip-wireguard
  else
    msg "HamVOIP bundle not found. Installing wireguard-tools."
    if pkg_installed hamvoip-wireguard; then
      echo "hamvoip-wireguard is installed and conflicts with wireguard-tools."
      if ask_yes_no "Remove hamvoip-wireguard and install wireguard-tools instead?" "N"; then
        pacman -Rns --noconfirm hamvoip-wireguard
      else
        echo "Keeping hamvoip-wireguard; skipping wireguard-tools."
        return 0
      fi
    fi
    pacman -S --noconfirm --needed wireguard-tools
  fi
}

# IPv4-only sanitize Address/AllowedIPs
sanitize_ipv4_only() {
  local in="$1" out="$2"
  awk '
    function trim(s){ sub(/^[ \t]+/,"",s); sub(/[ \t]+$/,"",s); return s }
    function is_ipv4(tok){ return (tok ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) }
    function join_ipv4(rhs,    n,i,t,acc,sep){
      gsub(/,/," ",rhs); n=split(rhs,t,/[\t ]+/)
      acc=""; sep=""
      for(i=1;i<=n;i++){ if(t[i]!="" && is_ipv4(t[i])){ acc=acc sep t[i]; sep=", " } }
      return acc
    }
    {
      line=$0
      if(line ~ /^[ \t]*\[/ || line ~ /^[ \t]*#/ || line ~ /^[ \t]*;/ || line ~ /^[ \t]*$/){ print line; next }
      split(line, parts, "="); if(length(parts)<2){ print line; next }
      key=trim(parts[1])
      rhs=line; sub(/^[^=]*=/,"",rhs); rhs=trim(rhs)
      if(key=="Address"){ v=join_ipv4(rhs); if(v!="") print "Address = " v; next }
      if(key=="AllowedIPs"){ v=join_ipv4(rhs); if(v=="") v="0.0.0.0/0"; print "AllowedIPs = " v; next }
      print line
    }
  ' "$in" > "$out"
}

detect_ssh_port() {
  awk 'BEGIN{p=22} /^[ \t]*Port[ \t]+[0-9]+/ && $1=="Port" {p=$2} END{print p}' /etc/ssh/sshd_config 2>/dev/null || echo 22
}

ensure_iptables() {
  if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables not found."
    if ask_yes_no "Install iptables now?" "Y"; then
      pacman -S --noconfirm --needed iptables
    else
      return 1
    fi
  fi
  command -v iptables-save >/dev/null 2>&1 || { echo "iptables-save not found; iptables package may be incomplete."; return 1; }
  command -v iptables-restore >/dev/null 2>&1 || { echo "iptables-restore not found; iptables package may be incomplete."; return 1; }
  return 0
}

# -------------------- PERSISTENCE (NEW) --------------------
save_iptables_rules() {
  install -d -m 0755 /etc/iptables
  iptables-save > /etc/iptables/iptables.rules
  echo "Saved rules to /etc/iptables/iptables.rules"
}

have_unit_file() {
  local unit="$1"
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"
}

install_fallback_restore_unit() {
  # Installs a generic template unit that restores from /etc/iptables/%i.rules
  # We will enable it as: iptables-restore@iptables.service (restores /etc/iptables/iptables.rules)
  local unit_path="/etc/systemd/system/iptables-restore@.service"
  if [[ ! -f "$unit_path" ]]; then
    cat > "$unit_path" <<'UNIT'
[Unit]
Description=Restore iptables rules from /etc/iptables/%i.rules
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/bin/iptables-restore -n /etc/iptables/%i.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    chmod 0644 "$unit_path"
    echo "Installed fallback unit: $unit_path"
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
}

enable_iptables_persistence() {
  # Always save current rules
  save_iptables_rules

  # Prefer distro-provided iptables.service when available
  if have_unit_file "iptables.service"; then
    systemctl enable iptables.service >/dev/null 2>&1 || true
    systemctl restart iptables.service >/dev/null 2>&1 || systemctl start iptables.service >/dev/null 2>&1 || true
    echo "Enabled iptables.service for persistence."
    return 0
  fi

  # Fallback: install our own restore unit and enable it
  install_fallback_restore_unit
  systemctl enable "iptables-restore@iptables.service" >/dev/null 2>&1 || true
  systemctl start  "iptables-restore@iptables.service" >/dev/null 2>&1 || true
  echo "Enabled fallback persistence via iptables-restore@iptables.service"
}

# ---- nounset-safe array helpers (bash 4.2+ compatible) ----
array_len() {
  local name="$1"
  if ! declare -p "$name" 2>/dev/null | grep -q 'declare \-a'; then
    echo 0
    return 0
  fi
  set +u
  eval "echo \${#${name}[@]}"
  set -u
}

array_join() {
  local name="$1"
  if ! declare -p "$name" 2>/dev/null | grep -q 'declare \-a'; then
    return 0
  fi
  set +u
  eval "printf '%s ' \"\${${name}[@]}\""
  set -u
}

declare -a EXTRA_TCP EXTRA_UDP
EXTRA_TCP=()
EXTRA_UDP=()

print_port_suggestions() {
  cat <<'EOF'
Suggested port sets you might want to allow (in addition to HTTP/SSH-from-LAN):
  1) AllStar (IAX2):                  UDP 4569
  2) EchoLink:                        UDP 5198-5199, TCP 5200
  3) Web (HTTP/HTTPS):                TCP 80, TCP 443
  4) Node-RED Dashboard (common):     TCP 1880 (Node-RED), TCP 3000 (Grafana), TCP 8086 (InfluxDB)
  5) Asterisk/SIP (if you use it):    UDP 5060-5061, TCP 5060-5061 (optional)
EOF
}

valid_port_token() {
  [[ "$1" =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]] || return 1
  local a b
  a="${1%-*}"
  b="${1#*-}"
  [[ -n "$a" ]] || return 1
  if [[ "$1" == *"-"* ]]; then
    [[ "$a" -ge 1 && "$a" -le 65535 && "$b" -ge 1 && "$b" -le 65535 && "$a" -le "$b" ]] || return 1
  else
    [[ "$a" -ge 1 && "$a" -le 65535 ]] || return 1
  fi
  return 0
}

collect_extra_ports() {
  EXTRA_TCP=()
  EXTRA_UDP=()
  EXTRA_TCP=()
  EXTRA_UDP=()

  echo
  print_port_suggestions
  echo

  if ! ask_yes_no "Do you want to add custom extra inbound ports beyond the defaults?" "N"; then
    return 0
  fi

  echo
  echo "Enter extra ports as a comma/space-separated list."
  echo "You can use single ports or ranges:"
  echo "  Examples: 80,443,8080 or 10000-10010"
  echo "Press Enter for none."
  echo

  local tcp_in udp_in tok
  read -rp "Extra TCP ports/ranges to ALLOW inbound (optional): " tcp_in || true
  read -rp "Extra UDP ports/ranges to ALLOW inbound (optional): " udp_in || true

  for tok in ${tcp_in//,/ }; do
    [[ -z "$tok" ]] && continue
    if valid_port_token "$tok"; then
      EXTRA_TCP+=("$tok")
    else
      echo "WARNING: ignoring invalid TCP port token: '$tok'"
    fi
  done

  for tok in ${udp_in//,/ }; do
    [[ -z "$tok" ]] && continue
    if valid_port_token "$tok"; then
      EXTRA_UDP+=("$tok")
    else
      echo "WARNING: ignoring invalid UDP port token: '$tok'"
    fi
  done
}

print_effective_port_plan() {
  local listen_port="$1"
  echo
  echo "Inbound ports that will be allowed:"
  echo "  - SSH from LAN only (tcp/${SSH_PORT})"
  [[ "${ALLOW_ALLSTAR:-false}" == "true" ]] && echo "  - AllStar:  udp/4569"
  [[ "${ALLOW_ECHOLINK:-false}" == "true" ]] && echo "  - EchoLink: udp/5198-5199, tcp/5200"
  [[ -n "${listen_port:-}" ]] && echo "  - WireGuard ListenPort: udp/${listen_port}"

  local tcp_len udp_len tcp_join udp_join
  tcp_len="$(array_len EXTRA_TCP)"
  udp_len="$(array_len EXTRA_UDP)"
  tcp_join="$(array_join EXTRA_TCP)"
  udp_join="$(array_join EXTRA_UDP)"

  if [[ "$tcp_len" -gt 0 ]]; then
    echo "  - Extra TCP: ${tcp_join}"
  fi
  if [[ "$udp_len" -gt 0 ]]; then
    echo "  - Extra UDP: ${udp_join}"
  fi
  echo
  echo "Everything else inbound will be BLOCKED."
}

apply_firewall_lockdown_iptables() {
  local cfg="$1"
  local listen_port
  SSH_PORT="$(detect_ssh_port)"
  listen_port="$(awk -F'=' '/^\s*ListenPort\s*=/ {gsub(/ /,"",$2); print $2}' "$cfg" | tr -d '[:space:]' || true)"

  msg "Firewall lockdown options (iptables)"
  echo "This is a DEFAULT-DENY inbound firewall."
  echo "HTTP/SSH will be allowed ONLY from private LAN ranges (10/8, 172.16/12, 192.168/16)."
  echo

  ALLOW_ALLSTAR="false"
  ALLOW_ECHOLINK="false"

  if ask_yes_no "Allow AllStar ports (recommended for AllStar nodes)? (udp/4569)" "Y"; then
    ALLOW_ALLSTAR="true"
  fi
  if ask_yes_no "Allow EchoLink ports (recommended if you run EchoLink)? (udp/5198-5199, tcp/5200)" "Y"; then
    ALLOW_ECHOLINK="true"
  fi

  collect_extra_ports
  print_effective_port_plan "$listen_port"

  echo "WARNING: If you are SSH'd in from a PUBLIC IP, enabling this will lock you out."
  echo "Make sure you have console access or you are on a private LAN before continuing."
  echo
  if ! ask_yes_no "Apply this firewall now?" "N"; then
    echo "Skipping firewall."
    return 0
  fi

  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -F
  iptables -X

  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -A INPUT -p icmp -j ACCEPT

  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -s 10.0.0.0/8 -j ACCEPT
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -s 172.16.0.0/12 -j ACCEPT
  iptables -A INPUT -p tcp --dport "${SSH_PORT}" -s 192.168.0.0/16 -j ACCEPT

  # CHANGE (ONLY): allow HTTP 80 from RFC1918 LAN ranges (LAN-only)
  iptables -A INPUT -p tcp --dport 80 -s 10.0.0.0/8 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -s 172.16.0.0/12 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -s 192.168.0.0/16 -j ACCEPT

  if [[ "$ALLOW_ALLSTAR" == "true" ]]; then
    iptables -A INPUT -p udp --dport 4569 -j ACCEPT
  fi
  if [[ "$ALLOW_ECHOLINK" == "true" ]]; then
    iptables -A INPUT -p udp --dport 5198:5199 -j ACCEPT
    iptables -A INPUT -p tcp --dport 5200 -j ACCEPT
  fi

  if [[ -n "${listen_port:-}" ]]; then
    iptables -A INPUT -p udp --dport "${listen_port}" -j ACCEPT
  fi

  local p
  if [[ "$(array_len EXTRA_TCP)" -gt 0 ]]; then
    for p in "${EXTRA_TCP[@]}"; do
      if [[ "$p" == *"-"* ]]; then
        iptables -A INPUT -p tcp --dport "${p/-/:}" -j ACCEPT
      else
        iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
      fi
    done
  fi

  if [[ "$(array_len EXTRA_UDP)" -gt 0 ]]; then
    for p in "${EXTRA_UDP[@]}"; do
      if [[ "$p" == *"-"* ]]; then
        iptables -A INPUT -p udp --dport "${p/-/:}" -j ACCEPT
      else
        iptables -A INPUT -p udp --dport "$p" -j ACCEPT
      fi
    done
  fi

  iptables -A INPUT -m limit --limit 5/second --limit-burst 20 -j LOG --log-prefix "iptables_lockdown drop: " --log-level 4

  echo "Applied iptables lockdown."

  # NEW: make it persist across reboot (guaranteed via distro unit or fallback unit)
  enable_iptables_persistence

  echo
  echo "Recovery (console):"
  echo "  sudo iptables -P INPUT ACCEPT; sudo iptables -F"
}

# ---------------- Main ----------------
require_root "$@"
need_cmd pacman

if ! is_arch_like; then
  echo "ERROR: This script is intended for HamVOIP / Arch ARM (pacman-based)."
  exit 1
fi

trap 'echo; echo "Exiting."; rm -f /tmp/wg_input.$$ /tmp/wg_final.$$ /tmp/wg_sanitized.$$ 2>/dev/null || true' EXIT

msg "0) System and kernel sanity check"
show_kernel_summary
if ! kernel_modules_ok; then
  echo "WARNING: /lib/modules/$(running_kernel) is missing."
fi

msg "1) Check for HamVOIP/Arch updates (and kernel packages), upgrade if needed"
do_pacman_refresh
UPDATES="$(pacman -Qu 2>/dev/null || true)"
if [[ -z "$UPDATES" ]]; then
  echo "No package updates available."
else
  echo "Updates available:"
  echo "------------------------------------------------------------"
  echo "$UPDATES"
  echo "------------------------------------------------------------"
  if ask_yes_no "Install these updates now?" "Y"; then
    REBOOT_LIKELY=false
    updates_requiring_reboot && REBOOT_LIKELY=true
    do_pacman_upgrade

    msg "Post-upgrade kernel check"
    show_kernel_summary
    RUN="$(running_kernel)"; LATEST="$(latest_module_dir)"
    if [[ -n "${LATEST:-}" && "$LATEST" != "$RUN" ]]; then
      echo
      echo "A newer kernel/modules appear to be installed on disk than you're currently running."
      echo "  Running: $RUN"
      echo "  Newest:  $LATEST"
      REBOOT_LIKELY=true
    fi

    if [[ "$REBOOT_LIKELY" == "true" ]] && ask_yes_no "Reboot now to load the latest kernel before WireGuard setup?" "Y"; then
      echo "Rebooting..."
      sync || true
      reboot
      exit 0
    fi
  else
    echo "Skipping upgrades."
  fi
fi

msg "2) Install WireGuard packages (conflict-safe)"
install_wireguard_packages

msg "3) Verify WireGuard kernel support"
modprobe wireguard 2>/dev/null || true
if ip link add wg0 type wireguard 2>/dev/null; then
  ip link del wg0 2>/dev/null || true
  echo "WireGuard kernel support OK"
else
  echo "WARNING: Could not create a WireGuard interface."
  echo "Diagnostics:"
  echo "  - Running kernel: $(uname -r)"
  echo "  - Module file(s):"
  find "/lib/modules/$(uname -r)" -iname 'wireguard.ko*' 2>/dev/null || true
  echo
  ask_yes_no "Continue anyway?" "N" || exit 1
fi

msg "4) Generating WireGuard keypair"
install -d -m 0700 /etc/wireguard
if [[ -f /etc/wireguard/privatekey || -f /etc/wireguard/publickey ]]; then
  echo "Existing keys detected in /etc/wireguard. Backing up."
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a /etc/wireguard/privatekey "/etc/wireguard/privatekey.bak.$ts" 2>/dev/null || true
  cp -a /etc/wireguard/publickey  "/etc/wireguard/publickey.bak.$ts" 2>/dev/null || true
fi
umask 077
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
PRIVKEY="$(cat /etc/wireguard/privatekey)"
PUBKEY="$(cat /etc/wireguard/publickey)"

echo "Your new WireGuard keys (save these securely):"
echo "  Private key: $PRIVKEY"
echo "  Public  key: $PUBKEY"
echo
echo ">> Copy the PUBLIC key and paste it into the tunnel setup prompt on your 44Net Cloud endpoint."
read -rp "Press Enter to continue..."

msg "5) Choose interface name"
read -rp "Enter interface name to create (default: wg0): " IFACE
IFACE="${IFACE:-wg0}"
CFG_TARGET="/etc/wireguard/${IFACE}.conf"

if [[ -f "$CFG_TARGET" ]]; then
  echo "An existing config $CFG_TARGET was found."
  if ask_yes_no "Backup and overwrite it?" "Y"; then
    cp -a "$CFG_TARGET" "${CFG_TARGET}.bak.$(date +%Y%m%d-%H%M%S)"
  else
    echo "Aborting to avoid overwriting."
    exit 1
  fi
fi

msg "6) Paste your WireGuard config below (IPv4 ONLY)"
cat <<'INSTR'
Paste your config (including [Interface] and [Peer] sections).
When finished, type a single line with:  EOF  then hit return.

IMPORTANT: This script enforces IPv4-only by keeping only IPv4 entries in:
  - Address =
  - AllowedIPs =
Any IPv6 items (fe80::..., ::/0, etc.) will be removed automatically.

Example (IPv4-only):
[Interface]
PrivateKey = REPLACE_ME
Address = 44.xx.xx.xx/24
DNS = 1.1.1.1,1.0.0.1
MTU = 1380

[Peer]
PublicKey = ProvidedByServer
Endpoint = x.x.x.x:xxxxx
PersistentKeepalive = 20
AllowedIPs = 0.0.0.0/0
INSTR
echo

: > /tmp/wg_input.$$
while IFS= read -r line; do
  [[ "$line" == "EOF" ]] && break
  printf "%s\n" "$line" >> /tmp/wg_input.$$
done

grep -q '^\s*\[Interface\]\s*$' /tmp/wg_input.$$ || { echo "Error: No [Interface] section detected. Aborting."; exit 1; }

cp /tmp/wg_input.$$ /tmp/wg_final.$$

if grep -q 'REPLACE_ME' /tmp/wg_final.$$; then
  sed -i -E "s|REPLACE_ME|$PRIVKEY|g" /tmp/wg_final.$$
elif grep -Eq '^[[:space:]]*PrivateKey[[:space:]]*=' /tmp/wg_final.$$; then
  sed -i -E "s|^[[:space:]]*PrivateKey[[:space:]]*=.*$|PrivateKey = $PRIVKEY|" /tmp/wg_final.$$
else
  awk -v pk="$PRIVKEY" '
    BEGIN{done=0}
    /^\s*\[Interface\]\s*$/ && !done { print; print "PrivateKey = " pk; done=1; next }
    { print }
  ' /tmp/wg_final.$$ > /tmp/wg_final.$$.new && mv /tmp/wg_final.$$.new /tmp/wg_final.$$
fi

if ! grep -Eq '^[[:space:]]*MTU[[:space:]]*=' /tmp/wg_final.$$; then
  awk '
    BEGIN{in_iface=0; done=0}
    /^\s*\[Interface\]\s*$/ {in_iface=1; print; next}
    /^\s*\[/ && $0 !~ /^\s*\[Interface\]\s*$/ {
      if(in_iface && !done){ print "MTU = 1380"; done=1 }
      in_iface=0
      print
      next
    }
    {
      if(in_iface && !done && $0 ~ /^[[:space:]]*PrivateKey[[:space:]]*=/){ print; print "MTU = 1380"; done=1; next }
      print
    }
    END{ if(in_iface && !done){ print "MTU = 1380" } }
  ' /tmp/wg_final.$$ > /tmp/wg_final.$$.new && mv /tmp/wg_final.$$.new /tmp/wg_final.$$
fi

sed -i 's/\r$//' /tmp/wg_final.$$
sed -i -E 's/[[:space:]]+$//' /tmp/wg_final.$$

sanitize_ipv4_only /tmp/wg_final.$$ /tmp/wg_sanitized.$$
mv /tmp/wg_sanitized.$$ /tmp/wg_final.$$

awk 'BEGIN{ok=0} /^\s*Address\s*=/ { if($0 ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) ok=1 } END{exit(ok?0:1)}' /tmp/wg_final.$$ \
  || { echo "ERROR: After sanitization, no IPv4 Address remained. Fix Address= and rerun."; exit 1; }

msg "7) Final config preview (${IFACE}.conf) (IPv4-only)"
echo "------------------------------------------------------------"
cat /tmp/wg_final.$$
echo "------------------------------------------------------------"
ask_yes_no "Accept and install to $CFG_TARGET?" "Y" || { echo "Aborted by user."; exit 1; }

install -m 600 /tmp/wg_final.$$ "$CFG_TARGET"

LISTEN_PORT="$(awk -F'=' '/^\s*ListenPort\s*=/ {gsub(/ /,"",$2); print $2}' "$CFG_TARGET" | tr -d '[:space:]' || true)"
[[ -n "${LISTEN_PORT:-}" ]] && echo "Detected WireGuard ListenPort: $LISTEN_PORT/udp"

msg "8) Bringing interface up: wg-quick up ${IFACE}"
wg-quick down "$IFACE" >/dev/null 2>&1 || true
if wg-quick up "$IFACE"; then
  echo
  echo "Interface ${IFACE} is up. Current status:"
  wg show "$IFACE" || true
else
  echo "Failed to bring ${IFACE} up."
  echo "Hints (last 50 lines):"
  journalctl -u "wg-quick@${IFACE}.service" --no-pager -n 50 2>/dev/null || true
  exit 1
fi

echo
if ask_yes_no "Enable auto-start at boot for ${IFACE}?" "Y"; then
  systemctl enable "wg-quick@${IFACE}.service" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "Enabled: wg-quick@${IFACE}.service"
else
  echo "Skipping enable at boot."
fi

msg "9) Optional firewall lockdown (iptables)"
echo "This step is OPTIONAL and will:"
echo "  - Block all inbound ports except your selected services and any extra ports you define"
echo "  - Restrict SSH to private LANs only (10/8, 172.16/12, 192.168/16)"
echo
if ensure_iptables; then
  apply_firewall_lockdown_iptables "$CFG_TARGET"
else
  echo "Skipping firewall (iptables not available)."
fi

msg "All done!"
echo "Config file: $CFG_TARGET"
echo
echo "Tips:"
echo "  - View status:      wg show $IFACE"
echo "  - Bring down/up:    wg-quick down $IFACE && wg-quick up $IFACE"
echo "  - Show firewall:    iptables -S"
echo "  - Verify persist:   ls -l /etc/iptables/iptables.rules; systemctl is-enabled iptables.service 2>/dev/null || systemctl is-enabled iptables-restore@iptables.service 2>/dev/null"
