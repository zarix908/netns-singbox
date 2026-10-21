//! Setup isolated netns + TUN + nftables, supervise tun2socks (Docker sing-box SOCKS upstream).

use std::ffi::CString;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use runns::{netns_name_ok, owner_stamp_path};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[derive(Clone, Debug)]
struct Config {
    netns_name: String,
    veth_host: String,
    veth_ns: String,
    host_gw: String,
    ns_gw: String,
    veth_cidr: String,
    socks_host: String,
    socks_port: u16,
    socks_routing_mark: String,
    socks_fwmark: u32,
    tun_device: String,
    tun_addr: String,
    tun_gw: String,
    tun2socks_bin: String,
    tun2socks_proxy: String,
    tun2socks_loglevel: String,
    tun2socks_mtu: u32,
    netns_nameservers: String,
    /// Account allowed to enter this netns via `runns` without being root. Empty: root only.
    netns_user: String,
}

impl Config {
    fn from_env() -> Config {
        let socks_host = env("SOCKS_HOST", "10.252.0.1");
        let socks_port = env_u16("SOCKS_PORT", 1080);
        let tun2socks_proxy = std::env::var("TUN2SOCKS_PROXY")
            .unwrap_or_else(|_| format!("socks5://{socks_host}:{socks_port}"));
        Config {
            netns_name: env("NETNS_NAME", "agent"),
            veth_host: env("VETH_HOST", "veth-agent-h"),
            veth_ns: env("VETH_NS", "veth-agent"),
            host_gw: env("HOST_GW", "10.252.0.1"),
            ns_gw: env("NS_GW", "10.252.0.2"),
            veth_cidr: env("VETH_CIDR", "10.252.0.0/30"),
            socks_host,
            socks_port,
            socks_routing_mark: env("SOCKS_ROUTING_MARK", "0x1337"),
            socks_fwmark: env_u32("SOCKS_FWMARK", 4919),
            tun_device: env("TUN_DEVICE", "tun0"),
            tun_addr: env("TUN_ADDR", "198.18.0.1/15"),
            tun_gw: env("TUN_GW", "198.18.0.1"),
            tun2socks_bin: env("TUN2SOCKS_BIN", "/usr/local/bin/tun2socks"),
            tun2socks_proxy,
            tun2socks_loglevel: env("TUN2SOCKS_LOGLEVEL", "info"),
            tun2socks_mtu: env_u32("TUN2SOCKS_MTU", 0),
            netns_nameservers: env("NETNS_NAMESERVERS", "1.1.1.1,8.8.8.8"),
            netns_user: env("NETNS_USER", ""),
        }
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn log(msg: impl AsRef<str>) {
    eprintln!("[netns-singbox] {}", msg.as_ref());
}

fn run_ok(program: &str, args: &[&str]) -> io::Result<()> {
    let out = Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(io::Error::other(format!(
            "{program} {args:?} → {}{}",
            out.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )))
    }
}

fn netns_exists(name: &str) -> io::Result<bool> {
    let out = Command::new("ip").args(["netns", "list"]).output()?;
    if !out.status.success() {
        return Err(io::Error::other("ip netns list failed"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().any(|n| n == name))
}

fn link_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ns(cfg: &Config, args: &[&str]) -> io::Result<()> {
    let mut full = vec!["netns", "exec", &cfg.netns_name];
    full.extend_from_slice(args);
    run_ok("ip", &full)
}

fn nft_rules(cfg: &Config) -> String {
    include_str!("isolation.nft.in")
        .replace("@VETH_NS@", &cfg.veth_ns)
        .replace("@SOCKS_HOST@", &cfg.socks_host)
        .replace("@SOCKS_PORT@", &cfg.socks_port.to_string())
        .replace("@SOCKS_ROUTING_MARK@", &cfg.socks_routing_mark)
}

fn install_netns_etc(cfg: &Config) -> io::Result<()> {
    let dir = format!("/etc/netns/{}", cfg.netns_name);
    std::fs::create_dir_all(&dir)?;
    let mut resolv = String::from("# Managed by netns-singbox\n");
    for ns in cfg
        .netns_nameservers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        resolv.push_str("nameserver ");
        resolv.push_str(ns);
        resolv.push('\n');
    }
    if !resolv.contains("nameserver ") {
        resolv.push_str("nameserver 1.1.1.1\n");
    }
    // UDP DNS via tun2socks needs SOCKS UDP; Docker often publishes 1080/tcp only — prefer TCP.
    resolv.push_str("options use-vc ndots:1\n");
    std::fs::write(format!("{dir}/resolv.conf"), resolv)?;

    let nsswitch = "\
# Managed by netns-singbox
passwd:         files systemd
group:          files systemd
shadow:         files systemd
gshadow:        files systemd
hosts:          files dns
networks:       files
protocols:      db files
services:       db files
ethers:         db files
rpc:            db files
netgroup:       nis
";
    std::fs::write(format!("{dir}/nsswitch.conf"), nsswitch)?;
    Ok(())
}

fn setup_tun(cfg: &Config) -> io::Result<()> {
    if !Command::new("ip")
        .args([
            "netns",
            "exec",
            &cfg.netns_name,
            "ip",
            "link",
            "show",
            &cfg.tun_device,
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        log(format!("creating {}", cfg.tun_device));
        ns(
            cfg,
            &["ip", "tuntap", "add", "mode", "tun", "dev", &cfg.tun_device],
        )?;
    }
    ns(
        cfg,
        &[
            "ip",
            "addr",
            "replace",
            &cfg.tun_addr,
            "dev",
            &cfg.tun_device,
        ],
    )?;
    ns(cfg, &["ip", "link", "set", "dev", &cfg.tun_device, "up"])?;
    ns(
        cfg,
        &[
            "ip",
            "route",
            "replace",
            "default",
            "via",
            &cfg.tun_gw,
            "dev",
            &cfg.tun_device,
            "metric",
            "1",
        ],
    )?;
    ns(
        cfg,
        &["sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0"],
    )?;
    ns(
        cfg,
        &[
            "sysctl",
            "-q",
            "-w",
            &format!("net.ipv4.conf.{}.rp_filter=0", cfg.veth_ns),
        ],
    )?;
    ns(
        cfg,
        &[
            "sysctl",
            "-q",
            "-w",
            &format!("net.ipv4.conf.{}.rp_filter=0", cfg.tun_device),
        ],
    )?;
    Ok(())
}

fn lookup_user(name: &str) -> io::Result<u32> {
    let mut buf = vec![0u8; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    if let Ok(c_name) = CString::new(name) {
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if !result.is_null() {
            return Ok(pwd.pw_uid);
        }
    }
    let uid: u32 = name
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("unknown user {name}")))?;
    result = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unknown uid {uid}"),
        ));
    }
    Ok(pwd.pw_uid)
}

/// Record which uid may `setns` into this netns via `runns`. Removed on teardown.
fn publish_netns_user(netns_name: &str, owner_uid: Option<u32>) -> io::Result<()> {
    let path = owner_stamp_path(netns_name);
    let Some(uid) = owner_uid else {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        return Ok(());
    };
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let tmp = path.with_extension("user.tmp");
    std::fs::write(&tmp, format!("{uid}\n"))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn setup(cfg: &Config) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "netns-singbox must run as root",
        ));
    }
    if !netns_name_ok(&cfg.netns_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NETNS_NAME must be a single path segment",
        ));
    }
    let user_name = cfg.netns_user.trim();
    let owner_uid = if user_name.is_empty() {
        None
    } else {
        Some(lookup_user(user_name)?)
    };

    let _ = Command::new("modprobe").arg("tun").status();

    if !netns_exists(&cfg.netns_name)? {
        log(format!("creating netns {}", cfg.netns_name));
        run_ok("ip", &["netns", "add", &cfg.netns_name])?;
    }

    if !link_exists(&cfg.veth_host) {
        log(format!(
            "creating veth {} <-> {}",
            cfg.veth_host, cfg.veth_ns
        ));
        run_ok(
            "ip",
            &[
                "link",
                "add",
                &cfg.veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &cfg.veth_ns,
            ],
        )?;
        run_ok(
            "ip",
            &["link", "set", &cfg.veth_ns, "netns", &cfg.netns_name],
        )?;
    }

    let _ = Command::new("ip")
        .args(["addr", "flush", "dev", &cfg.veth_host])
        .status();
    let _ = run_ok(
        "ip",
        &[
            "addr",
            "replace",
            &format!("{}/30", cfg.host_gw),
            "dev",
            &cfg.veth_host,
        ],
    );
    run_ok("ip", &["link", "set", &cfg.veth_host, "up"])?;

    ns(cfg, &["ip", "link", "set", "lo", "up"])?;
    let _ = ns(cfg, &["ip", "addr", "flush", "dev", &cfg.veth_ns]);
    let _ = run_ok(
        "ip",
        &[
            "netns",
            "exec",
            &cfg.netns_name,
            "ip",
            "addr",
            "replace",
            &format!("{}/30", cfg.ns_gw),
            "dev",
            &cfg.veth_ns,
        ],
    );
    ns(cfg, &["ip", "link", "set", &cfg.veth_ns, "up"])?;
    ns(
        cfg,
        &[
            "ip",
            "route",
            "replace",
            &cfg.veth_cidr,
            "dev",
            &cfg.veth_ns,
            "scope",
            "link",
        ],
    )?;

    setup_tun(cfg)?;
    install_netns_etc(cfg)?;

    let rules = nft_rules(cfg);
    let mut child = Command::new("ip")
        .args(["netns", "exec", &cfg.netns_name, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(rules.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other("nft apply failed"));
    }

    publish_netns_user(&cfg.netns_name, owner_uid)?;
    match owner_uid {
        Some(uid) => log(format!(
            "netns {} ready — uid {uid} may run: runns {} -- <cmd>",
            cfg.netns_name, cfg.netns_name
        )),
        None => log(format!(
            "netns {} ready — use runns {} -- <cmd> (root)",
            cfg.netns_name, cfg.netns_name
        )),
    }
    Ok(())
}

fn teardown(cfg: &Config) {
    log("teardown");
    if let Err(e) = publish_netns_user(&cfg.netns_name, None) {
        log(format!("remove owner stamp: {e}"));
    }
    if netns_exists(&cfg.netns_name).unwrap_or(false) {
        let _ = ns(cfg, &["nft", "flush", "ruleset"]);
        let _ = ns(cfg, &["ip", "link", "del", &cfg.tun_device]);
    }
    let _ = Command::new("ip")
        .args(["link", "del", &cfg.veth_host])
        .status();
    if netns_exists(&cfg.netns_name).unwrap_or(false) {
        let _ = run_ok("ip", &["netns", "del", &cfg.netns_name]);
    }
}

fn spawn_tun2socks(cfg: &Config) -> io::Result<Child> {
    let device = format!("tun://{}", cfg.tun_device);
    let mut cmd = Command::new("ip");
    cmd.args([
        "netns",
        "exec",
        &cfg.netns_name,
        &cfg.tun2socks_bin,
        "--device",
        &device,
        "--proxy",
        &cfg.tun2socks_proxy,
        "--interface",
        &cfg.veth_ns,
        "--fwmark",
        &cfg.socks_fwmark.to_string(),
        "--loglevel",
        &cfg.tun2socks_loglevel,
    ]);
    if cfg.tun2socks_mtu > 0 {
        cmd.args(["--mtu", &cfg.tun2socks_mtu.to_string()]);
    }
    cmd.stdin(Stdio::null()).spawn()
}

fn install_signals() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

fn main() {
    if let Err(e) = real_main() {
        log(format!("fatal: {e}"));
        std::process::exit(1);
    }
}

fn real_main() -> io::Result<()> {
    let cfg = Arc::new(Config::from_env());
    install_signals();

    setup(&cfg)?;

    let mut child = spawn_tun2socks(&cfg)?;
    log(format!(
        "tun2socks pid {} in netns {}",
        child.id(),
        cfg.netns_name
    ));

    let status = loop {
        if STOP.load(Ordering::SeqCst) {
            let _ = child.kill();
            let _ = child.wait();
            teardown(&cfg);
            return Ok(());
        }
        match child.try_wait()? {
            Some(st) => break st,
            None => thread::sleep(Duration::from_millis(200)),
        }
    };

    teardown(&cfg);

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("tun2socks exited: {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_root_user() {
        assert_eq!(lookup_user("root").unwrap(), 0);
        assert_eq!(lookup_user("0").unwrap(), 0);
    }

    #[test]
    fn lookup_unknown_user() {
        assert!(lookup_user("not-a-real-user-runns").is_err());
    }
}
