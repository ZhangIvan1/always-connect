//! Pure on-demand policy and probe wire formats. System I/O stays in the App.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Rule {
    pub id: String, pub name: String, pub network: String, pub ssids: Vec<String>,
    pub domains: Vec<String>, pub servers: Vec<String>, pub probe: Option<Probe>, pub action: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Probe { pub kind: String, pub target: String }
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Facts {
    pub network: Option<String>, pub ssid: Option<String>, pub domains: Vec<String>,
    pub servers: Vec<String>, pub probes: HashMap<String, bool>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Request { pub enabled: bool, pub rules: Vec<Rule>, pub facts: Facts }
#[derive(Debug, Serialize)]
pub struct Decision { pub action: String, pub rule_id: Option<String>, pub probe: Option<Probe> }
fn domain_match(p: &str, v: &str) -> bool {
    let p=p.trim_end_matches('.').to_ascii_lowercase(); let v=v.trim_end_matches('.').to_ascii_lowercase();
    if let Some(s)=p.strip_prefix("*.") { !s.is_empty() && v.ends_with(&format!(".{s}")) && v.len()>s.len()+1 }
    else { !p.is_empty() && p==v }
}
fn any(expected: &[String], actual: &[String], matches: impl Fn(&str,&str)->bool) -> bool {
    expected.is_empty() || expected.iter().any(|p|actual.iter().any(|v|matches(p,v)))
}
pub fn valid(r: &Rule) -> bool {
    !r.id.is_empty()
        && r.ssids.iter().all(|s| !s.is_empty())
        && r.domains.iter().all(|s| dns_query(s.strip_prefix("*.").unwrap_or(s)).is_some())
        && r.servers.iter().all(|s| s.parse::<std::net::IpAddr>().is_ok())
        && ["connect","disconnect","ignore"].contains(&r.action.as_str())
        && ["","any","wifi","wired"].contains(&r.network.as_str())
        && (r.network=="wifi" || r.network=="wired" || !r.ssids.is_empty() || !r.domains.is_empty() || !r.servers.is_empty() || r.probe.is_some())
        && r.probe.as_ref().is_none_or(|p|probe_plan(p).is_some())
}
pub fn decide(q: &Request) -> Decision {
    if q.enabled { for r in &q.rules {
        let f=&q.facts;
        if !valid(r) || (!r.network.is_empty() && r.network!="any" && f.network.as_deref()!=Some(&r.network)) {continue;}
        if !r.ssids.is_empty() && !f.ssid.as_ref().is_some_and(|s|r.ssids.contains(s)) {continue;}
        if !any(&r.domains,&f.domains,domain_match) {continue;}
        if !any(&r.servers,&f.servers,|p,v|p.parse::<std::net::IpAddr>().ok().zip(v.parse::<std::net::IpAddr>().ok()).is_some_and(|(p,v)|p==v)) {continue;}
        if let Some(p)=&r.probe {match f.probes.get(&r.id) {
            None=>return Decision{action:"probe".into(),rule_id:Some(r.id.clone()),probe:Some(p.clone())},
            Some(false)=>continue, Some(true)=>(),
        }}
        return Decision{action:r.action.clone(),rule_id:Some(r.id.clone()),probe:None};
    }}
    Decision{action:"connect".into(),rule_id:None,probe:None}
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Runtime {pub paused:bool,pub resume:bool,pub manual:bool,pub rule_id:Option<String>}
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Transition {pub state:Runtime,pub event:String,pub action:String,pub rule_id:Option<String>,pub active:bool,pub auto_connect:bool}
#[derive(Debug, Serialize)]
pub struct Effect {pub state:Runtime,pub effect:String}
pub fn transition(t:Transition)->Effect {
    let mut s=t.state; let mut effect="none";
    match t.event.as_str() {
        "manual"=>{s=Runtime{manual:true,..Default::default()};}
        "network"|"settings"=>{s.manual=false;}
        "decision" if !s.manual=>match t.action.as_str() {
            "disconnect"=>{s.resume|=t.active;s.paused=true;s.rule_id=t.rule_id;effect="disconnect";}
            "connect"=>{if (s.paused || (t.rule_id.is_some() && !t.active)) && (s.resume||t.auto_connect) {effect="connect";} s=Runtime::default();}
            _=>(),
        },_=>(),
    }
    Effect{state:s,effect:effect.into()}
}
#[derive(Debug, Serialize)]
pub struct ProbePlan {pub host:String,pub port:u16,pub tls:bool,pub request:Vec<u8>,pub dns_query:Vec<u8>,pub dns_query_v6:Vec<u8>}
fn dns_query(host:&str)->Option<Vec<u8>> {
    let host=host.trim_end_matches('.'); if host.is_empty()||host.len()>253{return None;}
    let mut q=vec![0x41,0x43,1,0,0,1,0,0,0,0,0,0];
    for l in host.split('.') {if l.is_empty()||l.len()>63||!l.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-'){return None;} q.push(l.len() as u8);q.extend(l.as_bytes());}
    q.extend([0,0,1,0,1]);Some(q)
}
pub fn probe_plan(p:&Probe)->Option<ProbePlan> {
    let (host,port,tls,request)=match p.kind.as_str() {
        "dns"=>(p.target.clone(),53,false,Vec::new()),
        "url"=>{
            let (tls,rest)=if let Some(s)=p.target.strip_prefix("https://"){(true,s)}else{(false,p.target.strip_prefix("http://")?)};
            if !rest.is_ascii()||rest.bytes().any(|b|b<=32||b==127)||rest.contains(['@','#']){return None;}
            let at=rest.find(['/','?']).unwrap_or(rest.len());let authority=&rest[..at];
            let (host,port)=match authority.split_once(':'){Some((h,p))=>(h,p.parse::<u16>().ok()?),None=>(authority,if tls{443}else{80})};
            if port==0{return None;}
            let path=if at==rest.len(){"/".into()}else if rest.as_bytes()[at]==b'?'{format!("/{}",&rest[at..])}else{rest[at..].into()};
            (host.into(),port,tls,format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").into_bytes())
        },_=>return None,
    };
    let dns_query=dns_query(&host)?; let mut dns_query_v6=dns_query.clone(); let n=dns_query_v6.len(); dns_query_v6[n-3]=28;
    Some(ProbePlan{dns_query,dns_query_v6,host,port,tls,request})
}
fn dns_addresses(b:&[u8])->Vec<String> {
    let mut ips=crate::dns_forwarder::ipv4_answers(b).iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut at=12;
    let qd=u16::from_be_bytes([b[4],b[5]]); let an=u16::from_be_bytes([b[6],b[7]]);
    for _ in 0..qd {let Some((_,end))=crate::dns_forwarder::read_name(b,at) else{return ips;}; at=end+4;}
    for _ in 0..an {
        let Some((_,end))=crate::dns_forwarder::read_name(b,at) else{break;};
        if end+10>b.len(){break;}
        let len=u16::from_be_bytes([b[end+8],b[end+9]]) as usize; let data=end+10;
        if data+len>b.len(){break;}
        if b[end..end+4]==[0,28,0,1] && len==16 {
            let octets: [u8;16]=b[data..data+16].try_into().unwrap(); ips.push(std::net::Ipv6Addr::from(octets).to_string());
        }
        at=data+len;
    }
    ips
}
pub fn probe_reply(kind:&str,b:&[u8])->serde_json::Value {
    if kind=="dns" {
        let ips=if b.len()>=12 && b[..2]==[0x41,0x43] && b[2]&0x82==0x80 && b[3]&15==0 {
            dns_addresses(b)
        }else{vec![]};serde_json::json!({"matched":!ips.is_empty(),"addresses":ips})
    }else{
        let line=b.split(|b|*b==b'\n').next().unwrap_or_default();let mut words=std::str::from_utf8(line).unwrap_or("").split_whitespace();
        serde_json::json!({"matched":(["HTTP/1.0","HTTP/1.1"].contains(&words.next().unwrap_or(""))&&words.next()==Some("200"))})
    }
}
#[cfg(test)] mod tests {
    use super::*;
    fn d(r:serde_json::Value,f:serde_json::Value)->Decision {decide(&serde_json::from_value(serde_json::json!({"enabled":true,"rules":r,"facts":f})).unwrap())}
    #[test] fn ordered_and_or_missing_default(){
        let r=serde_json::json!([{"id":"a","network":"wifi","ssids":["Office-WiFi","Lab"],"domains":["*.example.com","other.test"],"action":"disconnect"},{"id":"b","network":"wifi","action":"ignore"}]);
        assert_eq!(d(r.clone(),serde_json::json!({"network":"wifi","ssid":"Lab","domains":["CORP.Example.COM"]})).rule_id.as_deref(),Some("a"));
        assert_eq!(d(r.clone(),serde_json::json!({"network":"wifi","ssid":"lab","domains":["corp.example.com"]})).rule_id.as_deref(),Some("b"));
        assert_eq!(d(r.clone(),serde_json::json!({"network":"wifi"})).action,"ignore");
        assert_eq!(d(r,serde_json::json!({})).action,"connect");
        assert!(!domain_match("*.example.com","example.com"));assert!(!domain_match("*.example.com","notexample.com"));assert!(domain_match("EXAMPLE.COM.","example.com"));
        assert_eq!(decide(&Request::default()).action,"connect");
    }
    #[test] fn lazy_probes_and_invalid_empty(){
        let r=serde_json::json!([{"id":"a","ssids":["Office-WiFi"],"probe":{"kind":"dns","target":"intranet.example.com"},"action":"disconnect"},{"id":"b","servers":["10.0.0.53"],"action":"disconnect"}]);
        assert_eq!(d(r.clone(),serde_json::json!({})).action,"connect");
        assert_eq!(d(r.clone(),serde_json::json!({"ssid":"Office-WiFi"})).action,"probe");
        assert_eq!(d(r.clone(),serde_json::json!({"ssid":"Office-WiFi","probes":{"a":false}})).action,"connect");
        assert_eq!(d(r.clone(),serde_json::json!({"ssid":"Office-WiFi","probes":{"a":true}})).action,"disconnect");
        assert_eq!(d(r,serde_json::json!({"servers":["10.0.0.53"]})).rule_id.as_deref(),Some("b"));
        assert_eq!(d(serde_json::json!([{"id":"x","action":"disconnect"}]),serde_json::json!({})).action,"connect");
    }
    #[test] fn runtime_manual_ignore_resume(){
        let e=transition(Transition{event:"decision".into(),action:"disconnect".into(),active:true,..Default::default()});assert!(e.state.paused);assert_eq!(e.effect,"disconnect");
        let e=transition(Transition{state:e.state,event:"decision".into(),action:"ignore".into(),..Default::default()});assert!(e.state.paused);
        let e=transition(Transition{state:e.state,event:"decision".into(),action:"connect".into(),..Default::default()});assert!(!e.state.paused);assert_eq!(e.effect,"connect");
        let e=transition(Transition{event:"manual".into(),..Default::default()});
        let e=transition(Transition{state:e.state,event:"decision".into(),action:"disconnect".into(),..Default::default()});assert!(!e.state.paused);
        assert!(!transition(Transition{state:e.state,event:"network".into(),..Default::default()}).state.manual);
    }
    #[test] fn first_probe_precedes_later_rule_and_falls_through_on_failure() {
        let r=serde_json::json!([
            {"id":"a","network":"wired","probe":{"kind":"url","target":"https://intranet.example.com/"},"action":"ignore"},
            {"id":"b","network":"wired","action":"disconnect"}]);
        assert_eq!(d(r.clone(),serde_json::json!({"network":"wired"})).action,"probe");
        assert_eq!(d(r.clone(),serde_json::json!({"network":"wired","probes":{"a":true}})).action,"ignore");
        assert_eq!(d(r,serde_json::json!({"network":"wired","probes":{"a":false}})).rule_id.as_deref(),Some("b"));
    }
    #[test] fn dns_wire_addresses_and_errors() {
        let p=Probe{kind:"dns".into(),target:"intranet.example.com".into()}; let plan=probe_plan(&p).unwrap();
        let mut a=plan.dns_query.clone(); a[2]=0x81;a[3]=0x80;a[7]=1;
        a.extend([0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,10,0,0,53]);
        assert_eq!(probe_reply("dns",&a)["addresses"][0],"10.0.0.53");
        a[3]=0x83; assert_eq!(probe_reply("dns",&a)["matched"],false);
        let mut a=plan.dns_query_v6.clone();a[2]=0x81;a[3]=0x80;a[7]=1;
        a.extend([0xc0,0x0c,0,28,0,1,0,0,0,30,0,16]);
        a.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(probe_reply("dns",&a)["addresses"][0],"::1");
        a[0]=0;assert_eq!(probe_reply("dns",&a)["matched"],false);
    }
    #[test] fn invalid_conditions_are_not_disconnect_rules() {
        for r in [
            serde_json::json!({"id":"a","network":"any","action":"disconnect"}),
            serde_json::json!({"id":"a","servers":["invalid"],"action":"disconnect"}),
            serde_json::json!({"id":"a","domains":["*bad.example.com"],"action":"disconnect"})
        ] { assert_eq!(d(serde_json::json!([r]),serde_json::json!({})).action,"connect"); }
    }
    #[test] fn disabled_never_requests_a_probe() {
        let r=Rule{id:"a".into(),probe:Some(Probe{kind:"dns".into(),target:"example.com".into()}),action:"disconnect".into(),..Default::default()};
        assert_eq!(decide(&Request{enabled:false,rules:vec![r],..Default::default()}).action,"connect");
    }
    #[test] fn auto_connect_resumes_and_idle_off_does_not() {
        for (auto,expected) in [(true,"connect"),(false,"none")] {
            let e=transition(Transition{state:Runtime{paused:true,..Default::default()},event:"decision".into(),action:"connect".into(),auto_connect:auto,..Default::default()});
            assert_eq!(e.effect,expected);assert!(!e.state.paused);
        }
    }
    #[test] fn wire_validation(){
        for t in ["https://intranet.example.com/check","http://10.0.0.53/?a=b"]{assert!(probe_plan(&Probe{kind:"url".into(),target:t.into()}).is_some());}
        for t in ["file:///etc/hosts","https://user@host/","http://x/\r\nx","https://x:0/"]{assert!(probe_plan(&Probe{kind:"url".into(),target:t.into()}).is_none());}
        assert_eq!(probe_reply("url",b"HTTP/1.1 200 OK\r\n")["matched"],true);assert_eq!(probe_reply("url",b"HTTP/1.1 302 Found\r\n")["matched"],false);assert_eq!(probe_reply("dns",b"bad")["matched"],false);
    }
}
