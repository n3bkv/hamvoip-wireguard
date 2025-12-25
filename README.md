# HamVOIP WireGuard IPv4 Setup + Optional IPTables Firewall

This script provides a ***HamVOIP-compatible 44Net Connect WireGuard setup** with optional **iptables firewall lockdown**, specifically designed for:

- **HamVOIP / Arch ARM**
- **AllStarLink nodes**
- **IPv4-only 44Net Connect tunnels**
- Systems where **nftables are problematic or unavailable**

It avoids modern `nft` syntax and uses **iptables** for maximum compatibility with older HamVOIP builds.

---

## Features

- Installs WireGuard safely on HamVOIP / Arch ARM
- Handles package conflicts (`hamvoip-wireguard` vs `wireguard-tools`)
- Generates WireGuard keys
- Prompts for a 44Net Connect tunnel config and injects the private key
- Enforces **IPv4-only** (`Address=` and `AllowedIPs=`)
- Automatically adds:
  ```
  MTU = 1380
  ```
  under `[Interface]` 
- Brings up the tunnel with `wg-quick`
- Optional **iptables firewall lockdown**
- Interactive firewall setup selection of common ham services

---

## Recommended Use Cases

- AllStarLink nodes behind CGNAT
- Starlink / LTE / cellular WANs
- Systems where nftables breaks wg-quick

---

## Requirements

- HamVOIP or Arch ARM–based OS
- `pacman` package manager
- Root access (script auto-elevates with `sudo`)
- Console access recommended if enabling firewall

---

## Installation

```bash
curl -O https://raw.githubusercontent.com/n3bkv/hamvoip-wireguard/main/setup_hamvoip_wireguard.sh
chmod +x setup_hamvoip_wireguard.sh
sudo ./setup_hamvoip_wireguard.sh

```

---

## Example WireGuard Config (Prompted)

```ini
[Interface]
PrivateKey = REPLACE_ME
Address = 44.xx.xx.xx/24
DNS = 1.1.1.1,1.0.0.1
MTU = 1380

[Peer]
PublicKey = ProvidedByServer
Endpoint = x.x.x.x:51820
PersistentKeepalive = 20
AllowedIPs = 0.0.0.0/0
```

Notes:
- IPv6 entries are automatically stripped
- MTU is enforced if missing
- `REPLACE_ME` is replaced automatically

---

## Optional Firewall Lockdown (iptables)

If enabled, the script applies a **default-deny inbound firewall** with:

### Always Allowed
- Loopback
- Established/related connections
- ICMP
- SSH **only from RFC1918 LAN ranges**

### Optional Service Sets
- AllStarLink: `UDP 4569`
- EchoLink: `UDP 5198–5199`, `TCP 5200`
- WireGuard ListenPort (if defined)
- Custom TCP/UDP ports (single ports or ranges)

⚠️ **WARNING**  
If you are SSH’d in from a public IP, enabling the firewall **WILL LOCK YOU OUT**.  
Use console access or a private LAN connection.

---

## Firewall Recovery (Console)

```bash
iptables -P INPUT ACCEPT
iptables -F
```

---

## Post-Install Commands

```bash
wg show wg0
wg-quick down wg0
wg-quick up wg0
iptables -S
```

Enable tunnel at boot:
```bash
systemctl enable wg-quick@wg0
```

---

## Why MTU = 1380?

- Prevents fragmentation over:
  - Starlink
  - LTE / 5G
  - CGNAT
  - Nested VPNs
- Improves audio reliability for AllStar
- ***For T-Mobile edit wg0.conf file MTU value to 1280***
 

---

## Tested With

- HamVOIP on Raspberry Pi 4/5
- AllStarLink nodes
- Arch ARM kernels

---

##  License

MIT License © 2025 [n3bkv](https://github.com/n3bkv)

---

##  Contributions

Pull requests are welcome!  

---

## Support This Project

If you find this useful, star ⭐ the repo! It helps others discover it.

---

73, Dave N3BKV 
 
https://hamradiohacks.blogspot.com

https://hamradiohacks.n3bkv.com  

