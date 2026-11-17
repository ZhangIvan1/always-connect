//! Read-only checks of the configuration actually loaded by macOS (§48).
//! Decisions and parsers are Rust; no probe sends traffic or changes the network.
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    pub tunnel: Option<String>, pub dns_interface: Option<String>,
    pub physical: String, pub gateway: Option<String>, pub vpn_gateways: Vec<String>,
    pub dns: Vec<String>, pub split: bool, pub protection: bool,
    pub rules: Option<String>, pub direct: Vec<String>, pub routes: Vec<String>,
    pub error: Option<String>, pub epoch: u64,
}
#[derive(Serialize)]
pub struct Item { pub item: String, pub passed: bool, pub informational: bool, pub detail: String }
fn item(name: &str, passed: bool, detail: &str) -> Item {
    Item { item: name.into(), passed, informational: false, detail: detail.into() }
}
#[derive(Default, Clone)]
pub struct Output { pub ok: bool, pub text: String }

pub fn interface(output: &str) -> Option<&str> {
    output.lines().find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
}
fn first_dns(output: &str) -> Vec<String> {
    let mut servers = Vec::new();
    let mut begun = false;
    for line in output.lines().map(str::trim) {
        if line.starts_with("resolver #") {
            if begun { break; }
            begun = true;
        } else if begun && line.starts_with("DNS configuration") { break; }
        if begun && line.starts_with("nameserver[") {
            if let Some((_, value)) = line.split_once(':') { servers.push(value.trim().into()); }
        }
    }
    servers
}
fn expand_sets(text: &str) -> Vec<String> {
    let Some(a) = text.find('{') else { return vec![text.into()] };
    let Some(b) = text[a..].find('}').map(|b| b + a) else { return vec![text.into()] };
    text[a + 1..b].split_whitespace().flat_map(|v| expand_sets(&format!("{}{}{}", &text[..a], v.trim_end_matches(','), &text[b + 1..]))).collect()
}
/// Accept pfctl's normal formatting, not arbitrary extra rules. The generated
/// quick blocks keep their ordering barriers; pass expansion within a barrier is immaterial.
fn canonical_rules(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("table ")) {
        for line in expand_sets(line) {
            let mut line = format!(" {} ", line.split_whitespace().collect::<Vec<_>>().join(" "));
            line = line.replace(" keep state ", " ").replace(" port = ", " port ").replace(" user = ", " user ");
            line = line.replace(" all ", " from any to any ");
            if line.contains(" to ") && !line.contains(" from ") { line = line.replacen(" to ", " from any to ", 1); }
            let mut words: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
            let family = if words.iter().any(|w| w == "inet6") || words.iter().any(|w| w.split('/').next().is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok())) {
                Some("inet6")
            } else if words.iter().any(|w| w == "inet") || words.iter().any(|w| w.split('/').next().is_some_and(|s| s.parse::<std::net::Ipv4Addr>().is_ok())) { Some("inet") } else { None };
            words.retain(|w| w != "inet" && w != "inet6");
            let explicit_flags = if let Some(at) = words.iter().position(|w| w == "flags") {
                if at + 1 < words.len() { let flag = words[at + 1].clone(); words.drain(at..at + 2); Some(flag) }
                else { Some("invalid".into()) }
            } else { None };
            let tcp = words.first().map(String::as_str) == Some("pass")
                && words.iter().position(|w| w == "proto").map(|p| words.get(p + 1).map(String::as_str) == Some("tcp")).unwrap_or(true);
            if tcp {
                let stateless = words.windows(2).any(|w| w[0] == "no" && w[1] == "state");
                let flags = explicit_flags.unwrap_or_else(|| if stateless { "any".into() } else { "S/SA".into() });
                words.push(format!("tcp-flags={flags}"));
            } else if let Some(flags) = explicit_flags { if flags != "any" { words.push(format!("unexpected-flags={flags}")); } }
            for w in &mut words {
                *w = match w.as_str() { "root" => "0", "bootpc" => "68", "bootps" => "67", "domain" => "53", "mdns" => "5353", "icmp6" => "ipv6-icmp", "dhcpv6-client" => "546", "dhcpv6-server" => "547", _ => w }.to_owned();
                if w.ends_with("/32") { w.truncate(w.len() - 3); }
            }
            out.push(format!("{} {}", family.unwrap_or("both"), words.join(" ")));
        }
    }
    // Quick blocks are ordering barriers. Only passes within the same
    // barrier may be reordered by pfctl's set expansion.
    let mut ordered = Vec::new(); let mut passes = Vec::new();
    for rule in out {
        if rule.contains(" block ") { passes.sort(); passes.dedup(); ordered.append(&mut passes); ordered.push(rule); }
        else { passes.push(rule); }
    }
    passes.sort(); passes.dedup(); ordered.append(&mut passes); ordered
}
fn rules_match(actual: &str, expected: &str) -> bool {
    let lines: Vec<_> = actual.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    lines.last().is_some_and(|l| l.starts_with("block drop out quick") && (l.contains(" all") || l.contains("from any to any")))
        && canonical_rules(actual) == canonical_rules(expected)
}
fn destination(value: &str) -> Option<(u32, u32)> {
    let (ip, bits) = value.split_once('/').map(|(a,b)| (a, b.parse().ok())).unwrap_or((value, None));
    let mut parts: Vec<_> = ip.split('.').collect();
    if parts.len() > 4 { return None; }
    let prefix = bits.unwrap_or((parts.len() * 8) as u32);
    while parts.len() < 4 { parts.push("0"); }
    crate::dns_forwarder::cidr_range(&format!("{}/{prefix}", parts.join(".")))
}
fn routes_match(output: &str, expected: &Expected) -> bool {
    expected.routes.iter().all(|entry| {
        output.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() >= 4 && destination(fields[0]) == destination(entry)
                && fields[3] == expected.physical
                && expected.gateway.as_deref() == Some(fields[1])
        })
    })
}

/// Confirm the small, unconditional Apple wildcard/direct call chain. Unknown
/// filter rules and populated sibling anchors are conservatively unconfirmed.
fn anchor_calls(text: &str) -> Option<Vec<String>> {
    let lines:Vec<_>=text.lines().map(str::trim).filter(|s|!s.is_empty()&&!s.starts_with('#')&&!s.starts_with("scrub-anchor ")).collect();
    if lines.is_empty() || lines.len()>8 {return None;}
    lines.into_iter().map(|line| {
        let words:Vec<_>=line.split_whitespace().collect();
        if words.len()!=3 || words[0]!="anchor" || words[2]!="all" {return None;}
        Some(words[1].strip_prefix('"')?.strip_suffix('"')?.to_owned())
    }).collect()
}
fn anchor_call(text: &str) -> Option<String> {
    let mut calls=anchor_calls(text)?;
    if calls.len()==1 {calls.pop()} else {None}
}
fn anchor_chain(get: &mut impl FnMut(&str,&[&str])->Output) -> bool {
    let main=get("/sbin/pfctl",&["-s","rules"]); if !main.ok {return false;}
    let Some(calls)=anchor_calls(&main.text) else {return false;};
    let mut target=false;
    for name in calls {
        let current=match name.as_str() {
            crate::pf::ANCHOR=>Some(true),
            "com.apple/*"=>Some(apple_children(get)),
            "com.apple"=>{
                let parent=get("/sbin/pfctl",&["-a","com.apple","-s","rules"]);if !parent.ok{return false;}
                Some(match anchor_call(&parent.text).as_deref() {
                    Some("300.AlwaysConnect")|Some(crate::pf::ANCHOR)=>true,
                    Some("*")=>apple_children(get),_=>false,
                })
            },_=>None,
        };
        if let Some(reachable)=current {
            if target || !reachable {return false;}
            target=true;
        } else {
            // A vendor's bare anchor may coexist with ours, but only after
            // a successful read proves it contains no filtering rules.
            if name.is_empty() || name.starts_with('-') || !name.bytes().all(|c|c.is_ascii_alphanumeric()||b"._-".contains(&c)) {return false;}
            let other=get("/sbin/pfctl",&["-a",&name,"-s","rules"]);
            if !other.ok || !other.text.trim().is_empty() {return false;}
        }
    }
    target
}
fn apple_children(get: &mut impl FnMut(&str,&[&str])->Output) -> bool {
    let names=get("/sbin/pfctl",&["-a","com.apple","-s","Anchors"]);if !names.ok{return false;}
    let mut target=false;
    for name in names.text.lines().map(str::trim).filter(|s|!s.is_empty()) {
        let name=name.trim_matches('"').strip_prefix("com.apple/").unwrap_or(name.trim_matches('"'));
        if name=="300.AlwaysConnect" {target=true;continue;}
        if name.contains('/') || !name.bytes().all(|c|c.is_ascii_alphanumeric()||b"._-".contains(&c)) {return false;}
        let anchor=format!("com.apple/{name}");
        let other=get("/sbin/pfctl",&["-a",&anchor,"-s","rules"]);
        if !other.ok || !other.text.trim().is_empty() {return false;}
    }
    target
}

/// `exec` is injected in tests. Missing output, permission errors and deadlines
/// are failed observations, never inferred success from the engine's memory.
pub fn run_with(expected: &Expected, mut exec: impl FnMut(&str, &[String]) -> Output) -> Vec<Item> {
    let mut result = Vec::new();
    let Some(tunnel) = &expected.tunnel else { return vec![item("当前 VPN 路径", false, "没有已确认的隧道；不能确认 VPN 路径")]; };
    let mut get = |path: &str, args: &[&str]| exec(path, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let default = get("/sbin/route", &["-n", "get", "default"]);
    result.push(item("默认路由指向当前隧道", default.ok && interface(&default.text) == Some(tunnel), "读取系统实际默认路由，不比较公网出口 IP"));
    let scoped = get("/sbin/route", &["-n", "get", "-ifscope", tunnel, "default"]);
    result.push(item("绑定 VPN 网卡的 UDP/TCP 路径", scoped.ok && interface(&scoped.text) == Some(tunnel), "核对当前接口限定默认路由；浏览器选用候选仍需实测"));
    let dns = get("/usr/sbin/scutil", &["--dns"]);
    let mut dns_ok = dns.ok && !expected.dns.is_empty() && expected.dns_interface.as_ref() == Some(tunnel);
    if expected.split { dns_ok &= first_dns(&dns.text) == ["127.0.0.1"]; }
    else { let servers = first_dns(&dns.text); dns_ok &= !servers.is_empty() && servers.iter().all(|s| expected.dns.contains(s)); }
    for server in &expected.dns {
        let route = get("/sbin/route", &["-n", "get", "-ifscope", tunnel, server]);
        dns_ok &= route.ok && interface(&route.text) == Some(tunnel);
    }
    result.push(item("公司 DNS 配置与绑定路径", dns_ok, if expected.split { "系统只问本机转发器；核对本次 DNS 绑定与各上游限定路由" } else { "核对网关下发的 DNS 及当前隧道路由" }));
    let mut gateway_ok = !expected.vpn_gateways.is_empty();
    for gateway in &expected.vpn_gateways {
        let route = get("/sbin/route", &["-n", "get", gateway]);
        gateway_ok &= route.ok && interface(&route.text) == Some(expected.physical.as_str());
    }
    result.push(item("网关经当前物理口直连", gateway_ok, "核对实际网关路由"));
    let pf = get("/sbin/pfctl", &["-a", crate::pf::ANCHOR, "-s", "rules"]);
    let info = get("/sbin/pfctl", &["-s", "info"]);
    let enabled=info.ok&&info.text.contains("Status: Enabled");
    let reachable=if expected.protection {anchor_chain(&mut get)} else {false};
    let configured=pf.ok&&expected.rules.as_ref().is_some_and(|r|rules_match(&pf.text,r));
    let effective=enabled&&reachable&&configured;
    if expected.protection {
        result.push(item("实际防火墙配置与当前策略一致", effective && expected.error.is_none(), "完整核对实际规则；多放行、旧网卡、旧 DNS 和系统操作失败都不能通过"));
        result.push(item("pf 已开启", enabled, "读取系统实际过滤状态"));
        result.push(item("断线保护规则调用链已确认", reachable, "核对主/父锚点实际调用；额外过滤规则或未知分支显示未确认"));
        let ipv6_ok=effective && pf.text.lines().last().is_some_and(|l|l.trim().starts_with("block drop out quick"))
            && pf.text.contains("inet proto udp")&&!pf.text.contains(&format!("on {} all",expected.physical));
        result.push(item("物理公网 IPv6 受保护", ipv6_ok, "默认封堵包含 IPv6；DHCP 限 IPv4，链路本地发现保留；显式地址例外另计"));
        // The pre-existing broad tunnel allowance is visible, never a green
        // assertion that only this VPN can carry protected traffic.
        let other_tunnel = pf.text.lines().flat_map(expand_sets).any(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            words.windows(2).any(|w| w[0] == "on" && w[1].starts_with("utun") && w[1] != tunnel)
        });
        result.push(item("仅当前 VPN 隧道可作为出口", pf.ok && !other_tunnel, "规则仍允许其他 VPN 隧道，请避免同时启用其他隧道"));
        if expected.split {
            let table = get("/sbin/pfctl", &["-a", crate::pf::ANCHOR, "-t", crate::pf::DIRECT_TABLE, "-T", "show"]);
            let actual: BTreeSet<_> = table.text.split_whitespace().map(str::to_owned).collect();
            result.push(item("实际直连放行名单一致", table.ok && actual == expected.direct.iter().cloned().collect(), "核对内核中的完整 ac_direct 表，不读取缓存作为实际结果"));
        }
    } else {
        let mut off = item("断线保护", false, "使用者已关闭，不能据此确认断线或 IPv6 防漏"); off.informational = true; result.push(off);
    }
    let routes = get("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
    result.push(item("实际直连路由与当前网关一致", routes.ok && routes_match(&routes.text, expected), "核对本会话记账的全部直连主机/网段路由"));
    result
}

/// Bound every subprocess and the entire check, and bound captured output.
/// Only fixed system binaries and read-only arguments are used.
pub fn run(expected: &Expected) -> Vec<Item> {
    let deadline = Instant::now() + Duration::from_secs(2);
    run_with(expected, |path,args| read_command(path,args,deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(400))))
}

pub(crate) fn read_command(path: &str, args: &[String], limit: Duration) -> Output {
    if limit.is_zero() { return Output::default(); }
    let mut command=Command::new(path);
    let Ok(mut child) = crate::child_io::spawn(command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())) else { return Output::default() };
    let Some(stdout) = child.stdout.take() else { let _ = child.kill(); let _ = child.wait(); return Output::default() };
    let reader = std::thread::spawn(move || { let mut bytes = Vec::new(); let _ = stdout.take(512 * 1024 + 1).read_to_end(&mut bytes); bytes });
    let stop = Instant::now() + limit;
    let ok = loop {
        if let Ok(Some(status)) = child.try_wait() { break status.success(); }
        if Instant::now() >= stop { let _ = child.kill(); let _ = child.wait(); break false; }
        std::thread::sleep(Duration::from_millis(5));
    };
    let bytes = reader.join().unwrap_or_default();
    Output { ok: ok && bytes.len() <= 512 * 1024, text: String::from_utf8_lossy(&bytes).into_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Expected {
        let rules = crate::pf::generate(&crate::pf::PfInput { tunnel_if:"utun5".into(), physical_if:"en0".into(), gateway_ips:vec!["203.0.113.1".into()], allow_networks:vec!["192.168.0.0/16".into()], allow_direct_egress:false, allow_dns:false, dns_servers:vec!["192.168.1.1".into()],tunnel_dns_servers:vec!["10.1.1.1".into()],direct_table:true,strict_dns:false,block_direct:false }).unwrap();
        Expected { tunnel:Some("utun5".into()),dns_interface:Some("utun5".into()),physical:"en0".into(),gateway:Some("192.168.1.1".into()),vpn_gateways:vec!["203.0.113.1".into()],dns:vec!["10.1.1.1".into()],split:true,protection:true,rules:Some(rules),direct:vec!["198.51.100.9".into()],routes:vec!["198.51.100.9".into()],error:None,epoch:1 }
    }
    fn fixture(e:&Expected, path:&str,args:&[String]) -> Output {
        let text = if args==["-s","rules"] {"anchor \"com.apple/*\" all".into()}
        else if args==["-a","com.apple","-s","Anchors"] {"300.AlwaysConnect".into()}
        else if args==["-a","com.apple","-s","rules"] {String::new()}
        else if path.ends_with("route") { if args.last().map(String::as_str)==Some("203.0.113.1") { "interface: en0" } else { "interface: utun5" }.into() }
        else if args.last().map(String::as_str)==Some("--dns") { "resolver #1\\n  nameserver[0] : 127.0.0.1\\nresolver #2\\n  nameserver[0] : 192.168.1.1".replace("\\n","\n") }
        else if args.last().map(String::as_str)==Some("rules") { e.rules.clone().unwrap() }
        else if args.last().map(String::as_str)==Some("info") { "Status: Enabled".into() }
        else if args.last().map(String::as_str)==Some("show") { "198.51.100.9".into() }
        else { "Destination Gateway Flags Netif Expire\n198.51.100.9 192.168.1.1 UGHS en0".into() };
        Output{ok:true,text}
    }
    #[test]
    fn missing_parent_disabled_pf_or_earlier_pass_cannot_report_protection() {
        let e=expected();
        for main in ["","pass out quick all\nanchor \"com.apple/*\" all","anchor \"com.apple/*\" all\npass out quick all"] {
            let rows=run_with(&e,|p,a|if a==["-s","rules"] {Output{ok:true,text:main.into()}}else{fixture(&e,p,a)});
            for label in ["实际防火墙配置与当前策略一致","物理公网 IPv6 受保护"] {assert!(!rows.iter().find(|i|i.item==label).unwrap().passed);}
        }
        let rows=run_with(&e,|p,a|if a==["-s","info"] {Output{ok:true,text:"Status: Disabled".into()}}else{fixture(&e,p,a)});
        assert!(!rows.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
        let rows=run_with(&e,|p,a| {
            if a==["-a","com.apple","-s","Anchors"] {Output{ok:true,text:"100.Other\n300.AlwaysConnect".into()}}
            else if a==["-a","com.apple/100.Other","-s","rules"] {Output{ok:true,text:"pass out quick all".into()}}
            else{fixture(&e,p,a)}
        });
        assert!(!rows.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
        let direct=run_with(&e,|p,a|if a==["-s","rules"] {Output{ok:true,text:format!("anchor \"{}\" all",crate::pf::ANCHOR)}}else{fixture(&e,p,a)});
        assert!(direct.iter().find(|i|i.item=="物理公网 IPv6 受保护").unwrap().passed);
    }

    #[test]
    fn empty_vendor_anchor_must_not_hide_a_reachable_protection_anchor() {
        let e=expected();
        let main="scrub-anchor \"vendor.vpn\" all fragment reassemble\nanchor \"vendor.vpn\" all\nanchor \"com.apple/*\" all";
        let rows=run_with(&e,|p,a| {
            if a==["-s","rules"] {Output{ok:true,text:main.into()}}
            else if a==["-a","vendor.vpn","-s","rules"] {Output{ok:true,text:String::new()}}
            else {fixture(&e,p,a)}
        });
        assert!(rows.iter().find(|i|i.item=="断线保护规则调用链已确认").unwrap().passed,
            "an inspected empty sibling cannot bypass our outbound protection");
        for (ok,text) in [(false,""),(true,"pass out quick all"),(true,"anchor \"unknown/*\" all")] {
            let rows=run_with(&e,|p,a| {
                if a==["-s","rules"] {Output{ok:true,text:main.into()}}
                else if a==["-a","vendor.vpn","-s","rules"] {Output{ok,text:text.into()}}
                else {fixture(&e,p,a)}
            });
            assert!(!rows.iter().find(|i|i.item=="断线保护规则调用链已确认").unwrap().passed,
                "unknown or populated vendor rules must stay unconfirmed");
        }
    }

    #[test]
    fn loaded_config_not_cached_intent_determines_the_verdict() {
        let e=expected(); let good=run_with(&e,|p,a|fixture(&e,p,a));
        assert!(good.iter().filter(|i|i.item!="仅当前 VPN 隧道可作为出口").all(|i|i.passed));
        assert!(!good.iter().find(|i|i.item=="仅当前 VPN 隧道可作为出口").unwrap().passed);
        for corruption in ["route","dns","rules","table","gateway","info","netstat"] {
            let rows=run_with(&e,|p,a|{
                let mut out=fixture(&e,p,a);
                if (corruption=="route"&&p.ends_with("route")) || (corruption=="dns"&&p.ends_with("scutil"))
                    || (corruption=="rules"&&a.last().map(String::as_str)==Some("rules"))
                    || (corruption=="table"&&a.last().map(String::as_str)==Some("show"))
                    || (corruption=="gateway"&&a.last().map(String::as_str)==Some("203.0.113.1"))
                    || (corruption=="info"&&a.last().map(String::as_str)==Some("info"))
                    || (corruption=="netstat"&&p.ends_with("netstat")) {out.text="stale or unavailable".into();}
                out
            });
            assert!(rows.iter().filter(|i|i.item!="仅当前 VPN 隧道可作为出口").any(|i|!i.passed),"{corruption}");
        }
    }
    #[test]
    fn kernel_parser_output_matches_implicit_flags_and_deduplicated_passes() {
        let source = include_str!("../tests/fixtures/pf-source.conf");
        let actual = include_str!("../tests/fixtures/pf-compiled.conf");
        assert!(rules_match(actual, source));
        let too_strict = actual.replace("on lo0 all no state", "on lo0 all flags S/SA no state");
        assert!(!rules_match(&too_strict, source), "SYN-only pass cannot replace flags-any no-state pass");
        let broader = actual.replace("fe80::/10 flags S/SA keep state", "fe80::/10 flags any keep state");
        assert!(!rules_match(&broader, source), "explicit flags-any differs from the stateful default");
    }

    #[test]
    fn pf_printer_variants_match_but_extra_passes_and_early_blocks_do_not() {
        let e=expected();let rules=e.rules.unwrap();
        let formatted=rules.replace(" no state", " flags any no state").replace(" port 53 no state", " port = domain no state");
        assert_eq!(canonical_rules(&rules),canonical_rules(&formatted));
        let loaded=rules.lines().filter(|l|!l.starts_with('#')&&!l.starts_with("table ")).collect::<Vec<_>>().join("\n");
        assert!(rules_match(&loaded,&rules));
        assert!(!rules_match(&format!("pass out quick all\n{loaded}"),&rules));
        assert!(!rules_match(&format!("block drop out quick all\n{loaded}\npass out quick all"),&rules));
        let deny = "block drop out quick proto { udp tcp } to any port 53";
        let late_deny = loaded.replace(&format!("{deny}\n"), "").replace("block drop out quick all", &format!("{deny}\nblock drop out quick all"));
        assert!(!rules_match(&late_deny, &rules), "moving DNS denial below LAN exceptions must fail");
        assert_eq!(destination("10.20/16"),destination("10.20.0.0/16"));
        assert_eq!(first_dns("resolver #1\n nameserver[0] : 127.0.0.1\nDNS configuration (for scoped queries)\nresolver #1\n nameserver[0] : 192.168.1.1"),vec!["127.0.0.1"]);
    }
}
