# gh-allow.sh

Toggle your VM’s egress between **LAB** (GitHub-only + SSH from host) and **NORMAL** (open internet) with one command.  

---
## What it does

- **LAB mode:**
    
    - Outbound: only `github.com` + related domains on **443/22**
    - DNS: only the resolvers you allow (defaults: `10.0.2.3, 1.1.1.1, 9.9.9.9`)
    - Inbound: **drop**, except **SSH from host** (defaults to gateway `10.0.2.2`)
    
- **NORMAL mode:**
    
    - Outbound: **accept all**
    - Inbound: **default-drop** (loopback + established allowed)

The script creates an nftables table and manages allowlists

---

## Tested on

- **Debian 12 (bookworm)** inside QEMU with **user-net (slirp)**
    
    - Typical gateway (host): `10.0.2.2`
    - Typical DNS (slirp): `10.0.2.3`

Works with bridged/tap too - overrides `HOST_IP` to your gateway.

---

## Requirements

`sudo apt install -y nftables curl   # required

---

## Install

`sudo install -m755 netmode.sh /usr/local/bin/netmode`

---

## Usage
```
gh-allow on       # LAB: GitHub-only egress + SSH from host 
gh-allow off      # NORMAL: open egress, inbound default-drop 
gh-allow toggle   # switch between LAB and NORMAL
gh-allow update   # refresh GitHub IP allowlists (run after 'on')
gh-allow status   # print current mode
gh-allow test     # quick connectivity checks
```

### QEMU example

User-net with SSH forward (recommended):

`-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \ -device e1000,netdev=net0,id=nic0`

Then from the host: `ssh -p 2222 <user>@127.0.0.1`.

---

## Configuration (env vars)

| Variable  | Default                                           | Description                                 |
| --------- | ------------------------------------------------- | ------------------------------------------- |
| `HOST_IP` | auto-detected default route (fallback `10.0.2.2`) | Host/gateway IP allowed to reach guest SSH. |
| `NFT`     | `/usr/sbin/nft`                                   | Path to nft binary.                         |

Example:

`HOST_IP=192.168.56.1 gh-allow on`

---

## How it works (short)

- Creates `table inet outlock` with sets:
    
    - `gh4` / `gh6`: IPv4/IPv6 allowlists for GitHub domains
    - `dns4`: IPv4 resolvers allowed for DNS
        
- LAB chains:
    
    - `input`: loopback + established, **SSH from $HOST_IP**, else drop
    - `output`: established, **DNS only to @dns4**, **HTTPS/SSH only to @gh{4,6}**, else reject
        
- NORMAL chains:
    
    - `output`: accept
    - `input`: loopback + established, else drop

IPv6 is supported (allowlist populated if you use it), but QEMU user-net is primarily IPv4—LAB mode prefers v4.

---

## Quick tests

```
gh-allow on && gh-allow update
curl -4I https://github.com         # 200/301 ✅
curl -4I https://google.com         # should FAIL ❌
ssh -T -p 443 git@ssh.github.com    # "Permission denied (publickey)." is OK 
gh-allow off 
curl -4I https://google.com         # works ✅
```

---

## Security notes

- Use **user-net** (slirp) for NAT isolation; avoid shared folders and host clipboard bridges.
- Bind VNC/SPICE to **localhost** only if used.
- Prefer snapshots/`-snapshot` for detonation runs.
- This script **does not** grant capture permissions; Wireshark/TCP dump capabilities are separate.

---

## Optional: systemd unit (start in LAB at boot)

`systemd/lab-net.service`

```
[Unit]
  Description=QEMU Lab Net gh-allow (GitHub-only) 
  After=network-online.target 
  Wants=network-online.target  
[Service] 
  Type=oneshot 
  ExecStart=/usr/local/bin/gh-allow on 
  RemainAfterExit=yes  
[Install] 
  WantedBy=multi-user.target
```

Enable:

`sudo cp systemd/lab-net.service /etc/systemd/system/ sudo systemctl enable --now lab-net.service`

---

## Troubleshooting

- **Locked out / no internet** → `netmode panic` then `netmode off`.
- **LAB blocks GitHub** → ensure `netmode update` ran _after_ `netmode on`; check sets:
    
    `sudo nft list set inet outlock gh4`
    
- **Using a bridge** → set `HOST_IP` to your bridge/gateway.

---

## License

MIT. See `LICENSE`.

---

## Credits

Built for repeatable reverse-engineering labs on Debian/QEMU. Contributions welcome!
## Credits

Built for repeatable reverse-engineering labs on Debian/QEMU. Contributions welcome!
