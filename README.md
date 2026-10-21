# netns-singbox

Isolated network namespace (TUN → tun2socks → Docker sing-box SOCKS). Installs under **`/opt/netns-singbox/`** via [Task](https://taskfile.dev).

## Layout

```text
/opt/netns-singbox/
  bin/netns-singbox
  bin/tun2socks          # you install (xjasonlyu/tun2socks release)
  env
  env.example
  README.md

/etc/systemd/system/netns-singbox.service   # installed by task install
```

## Install

Requires [go-task](https://taskfile.dev/installation/) (`task` on PATH).

```bash
cd happ_sing_box && docker compose up -d

cd netns-singbox
task build
sudo task install

sudo install -m755 /path/to/tun2socks /opt/netns-singbox/bin/tun2socks
# edit /opt/netns-singbox/env
sudo task start
```

From repo root:

```bash
task netns-singbox:build
sudo task netns-singbox:install
sudo task netns-singbox:start
task netns-singbox:status
```

## Tasks

| Task | Description |
|------|-------------|
| `task build` | `cargo build --release` in this directory (no root) |
| `sudo task install` | Copy built binary to `/opt/netns-singbox`, install systemd unit |
| `sudo task uninstall` | Remove opt tree, unit file, disable service |
| `sudo task start` / `stop` | systemctl |
| `task status` / `logs` | Service status / journal |

Run workloads with [runns](../runns/): `sudo runns "$NETNS_NAME" -- curl …`

That runs the command as the user who invoked sudo. The unit stays root: `User=` cannot own this namespace, because veth, TUN, and nftables are created in the initial user namespace. The namespace stays root-owned so the command cannot rewrite the firewall; `runns` drops to your uid and clears capabilities before exec.

### Service fails at `ip netns add` / `mount --make-shared /run/netns`

The unit needs **`CAP_SYS_ADMIN`** (see `systemd/netns-singbox.service`). After updating the unit: `sudo task install` (or copy the unit file) and `sudo systemctl daemon-reload && sudo systemctl restart netns-singbox`.

Source is this directory (`src/main.rs`). The owner-stamp protocol it shares with `runns` lives in the [`runns`](../runns/) library.
