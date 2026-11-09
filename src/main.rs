use anyhow::{bail, Context, Result};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::{atomic::{AtomicU64, Ordering}, Arc}, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::{RwLock, Semaphore}};
use tracing::{debug, info, info_span, warn, Instrument};
use rand_core::OsRng;

const MAX_HEADER: usize = 64 * 1024;
const IDLE_TIMEOUT_SECS: u64 = 60;

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "proxy.db")]
    db: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")] listen: String,
        #[arg(long)] admin_listen: Option<String>,
    },
    AddUser { email: String, #[arg(long)] password: String },
    RemoveUser { email: String },
    ListUsers,
    AddDomain { pattern: String },
    RemoveDomain { pattern: String },
    ListDomains,
}

#[derive(Clone)]
struct Policy {
    users: Arc<HashMap<String, String>>,
    domains: Arc<Vec<String>>,
}

#[derive(Default)]
struct Metrics {
    active_connections: AtomicU64,
    total_connections: AtomicU64,
    auth_success: AtomicU64,
    auth_failures: AtomicU64,
    denied_domains: AtomicU64,
    upstream_errors: AtomicU64,
    bytes_client_to_upstream: AtomicU64,
    bytes_upstream_to_client: AtomicU64,
    auth_cache_hits: AtomicU64,
    next_request_id: AtomicU64,
}

struct ActiveConnection(Arc<Metrics>);
impl Drop for ActiveConnection {
    fn drop(&mut self) { self.0.active_connections.fetch_sub(1, Ordering::Relaxed); }
}

impl Metrics {
    fn json(&self) -> String {
        format!(r#"{{"active_connections":{},"total_connections":{},"auth_success":{},"auth_failures":{},"auth_cache_hits":{},"denied_domains":{},"upstream_errors":{},"bytes_client_to_upstream":{},"bytes_upstream_to_client":{}}}"#,
            self.active_connections.load(Ordering::Relaxed), self.total_connections.load(Ordering::Relaxed),
            self.auth_success.load(Ordering::Relaxed), self.auth_failures.load(Ordering::Relaxed),
            self.auth_cache_hits.load(Ordering::Relaxed),
            self.denied_domains.load(Ordering::Relaxed), self.upstream_errors.load(Ordering::Relaxed),
            self.bytes_client_to_upstream.load(Ordering::Relaxed), self.bytes_upstream_to_client.load(Ordering::Relaxed))
    }

    fn prometheus(&self) -> String {
        format!("# TYPE managed_proxy_active_connections gauge\nmanaged_proxy_active_connections {}\n# TYPE managed_proxy_total_connections counter\nmanaged_proxy_total_connections {}\n# TYPE managed_proxy_auth_success counter\nmanaged_proxy_auth_success {}\n# TYPE managed_proxy_auth_failures counter\nmanaged_proxy_auth_failures {}\n# TYPE managed_proxy_auth_cache_hits counter\nmanaged_proxy_auth_cache_hits {}\n# TYPE managed_proxy_denied_domains counter\nmanaged_proxy_denied_domains {}\n# TYPE managed_proxy_upstream_errors counter\nmanaged_proxy_upstream_errors {}\n# TYPE managed_proxy_bytes_client_to_upstream counter\nmanaged_proxy_bytes_client_to_upstream {}\n# TYPE managed_proxy_bytes_upstream_to_client counter\nmanaged_proxy_bytes_upstream_to_client {}\n",
            self.active_connections.load(Ordering::Relaxed), self.total_connections.load(Ordering::Relaxed),
            self.auth_success.load(Ordering::Relaxed), self.auth_failures.load(Ordering::Relaxed),
            self.auth_cache_hits.load(Ordering::Relaxed),
            self.denied_domains.load(Ordering::Relaxed), self.upstream_errors.load(Ordering::Relaxed),
            self.bytes_client_to_upstream.load(Ordering::Relaxed), self.bytes_upstream_to_client.load(Ordering::Relaxed))
    }
}

impl Policy {
    fn load(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        init_db(&conn)?;
        let mut users = HashMap::new();
        let mut stmt = conn.prepare("SELECT email, password_hash FROM users WHERE active=1")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (email, hash) = row?;
            users.insert(email, hash);
        }
        let mut domains = Vec::new();
        let mut stmt = conn.prepare("SELECT pattern FROM domains WHERE active=1")?;
        for row in stmt.query_map([], |r| r.get::<_, String>(0))? { domains.push(row?); }
        Ok(Self { users: Arc::new(users), domains: Arc::new(domains) })
    }

    fn auth(&self, header: Option<&str>) -> bool {
        let Some(value) = header else { return false };
        let Some(encoded) = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) else { return false };
        let Ok(decoded) = STANDARD.decode(encoded.trim()) else { return false };
        let Ok(credentials) = String::from_utf8(decoded) else { return false };
        let Some((email, password)) = credentials.split_once(':') else { return false };
        let Some(hash) = self.users.get(&email.to_lowercase()) else { return false };
        let Ok(parsed) = PasswordHash::new(hash) else { return false };
        Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
    }

    fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|pattern| host == *pattern || host.ends_with(&format!(".{pattern}")))
    }
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1); CREATE TABLE IF NOT EXISTS domains(pattern TEXT PRIMARY KEY COLLATE NOCASE, active INTEGER NOT NULL DEFAULT 1);")?;
    Ok(())
}

fn normalize_domain(s: &str) -> Result<String> {
    let value = s.trim().trim_start_matches("*.").trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.contains('/') || value.contains(':') { bail!("invalid domain") }
    Ok(value)
}

fn password_hash(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))
}

async fn serve(db: String, listen: String, admin_listen: Option<String>) -> Result<()> {
    let policy = Arc::new(RwLock::new(Policy::load(&db)?));
    let metrics = Arc::new(Metrics::default());
    let auth_cache = Arc::new(RwLock::new(HashMap::<[u8; 32], Instant>::new()));
    let auth_cache_ttl = Duration::from_secs(std::env::var("AUTH_CACHE_TTL_SECS").ok()
        .and_then(|value| value.parse::<u64>().ok()).unwrap_or(30));
    let auth_parallelism = std::env::var("AUTH_CONCURRENCY").ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(4);
    let auth_limiter = Arc::new(Semaphore::new(auth_parallelism));
    let policy_refresh = policy.clone();
    let refresh_db = db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match Policy::load(&refresh_db) {
                Ok(next) => *policy_refresh.write().await = next,
                Err(error) => warn!(%error, "policy refresh failed"),
            }
        }
    });
    let listener = TcpListener::bind(&listen).await?;
    info!(%listen, "proxy listening");
    if let Some(admin_address) = admin_listen {
        let admin_metrics = metrics.clone();
        let admin_token = std::env::var("ADMIN_TOKEN").context("ADMIN_TOKEN is required with --admin-listen")?;
        let admin_bind = admin_address.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_admin(&admin_bind, admin_token, admin_metrics, db).await { warn!(%error, "admin server stopped"); }
        });
        info!(listen = %admin_address, "admin dashboard listening");
    }
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let policy = policy.clone();
        let auth_limiter = auth_limiter.clone();
        let metrics = metrics.clone();
        let auth_cache = auth_cache.clone();
        let request_id = metrics.next_request_id.fetch_add(1, Ordering::Relaxed) + 1;
        let span = info_span!("proxy_connection", request_id, peer = %peer);
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, policy, auth_limiter, metrics, auth_cache, auth_cache_ttl).await { warn!(%error, "connection failed"); }
        }.instrument(span));
    }
}

async fn handle_client(mut client: TcpStream, policy: Arc<RwLock<Policy>>, auth_limiter: Arc<Semaphore>, metrics: Arc<Metrics>, auth_cache: Arc<RwLock<HashMap<[u8; 32], Instant>>>, auth_cache_ttl: Duration) -> Result<()> {
    let started = Instant::now();
    metrics.total_connections.fetch_add(1, Ordering::Relaxed);
    metrics.active_connections.fetch_add(1, Ordering::Relaxed);
    let _active = ActiveConnection(metrics.clone());
    let mut buffer = Vec::with_capacity(8192);
    read_headers(&mut client, &mut buffer).await?;
    let mut request = parse_request(&buffer)?;
    let snapshot = policy.read().await.clone();
    let auth_header = request.header("proxy-authorization").map(ToOwned::to_owned);
    let cache_key = auth_header.as_deref().map(|value| Sha256::digest(value.as_bytes()).into());
    let cached = if let Some(key) = cache_key {
        auth_cache.read().await.get(&key).is_some_and(|expires| *expires > Instant::now())
    } else { false };
    let authenticated = if cached {
        metrics.auth_cache_hits.fetch_add(1, Ordering::Relaxed);
        debug!("proxy credential cache hit");
        true
    } else {
        let auth_permit = auth_limiter.acquire().await?;
        let result = tokio::task::spawn_blocking(move || snapshot.auth(auth_header.as_deref())).await?;
        drop(auth_permit);
        if result {
            if let Some(key) = cache_key { auth_cache.write().await.insert(key, Instant::now() + auth_cache_ttl); }
        }
        result
    };
    let snapshot = policy.read().await.clone();
    if !authenticated {
        metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(reason = "invalid_proxy_credentials", "proxy authentication rejected");
        client.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=managed-proxy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        return Ok(());
    }
    metrics.auth_success.fetch_add(1, Ordering::Relaxed);
    let (target_host, port) = target(&request)?;
    let host = target_host.to_owned();
    if !snapshot.allows(&host) {
        metrics.denied_domains.fetch_add(1, Ordering::Relaxed);
        warn!(host = %host, reason = "domain_not_allowlisted", "upstream domain rejected");
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        return Ok(());
    }
    let mut upstream = match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(stream)) => stream,
        _ => {
            metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
            warn!(host = %host, port, reason = "upstream_connect_failed", "upstream connection failed");
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Ok(())
        }
    };
    upstream.set_nodelay(true)?;
    if request.method.eq_ignore_ascii_case("CONNECT") {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        if let Ok(Ok((to_upstream, to_client))) = tokio::time::timeout(std::time::Duration::from_secs(IDLE_TIMEOUT_SECS), tokio::io::copy_bidirectional(&mut client, &mut upstream)).await {
            metrics.bytes_client_to_upstream.fetch_add(to_upstream, Ordering::Relaxed);
            metrics.bytes_upstream_to_client.fetch_add(to_client, Ordering::Relaxed);
            info!(protocol = "connect", host = %host, port, bytes_client_to_upstream = to_upstream, bytes_upstream_to_client = to_client, elapsed_ms = started.elapsed().as_millis() as u64, "proxy connection completed");
        }
        return Ok(());
    }
    let content_length = request.header("content-length").unwrap_or("0").parse::<usize>().unwrap_or(0);
    let header_end = request.header_end;
    while request.raw.len().saturating_sub(header_end) < content_length {
        let mut chunk = [0u8; 16 * 1024];
        let count = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut chunk)).await??;
        if count == 0 { bail!("client closed before request body was complete") }
        request.raw.extend_from_slice(&chunk[..count]);
    }
    let rewritten = rewrite_http_request(&request)?;
    upstream.write_all(&rewritten).await?;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(IDLE_TIMEOUT_SECS), tokio::io::copy(&mut upstream, &mut client)).await?;
    info!(protocol = "http", method = %request.method, host = %host, port, elapsed_ms = started.elapsed().as_millis() as u64, "proxy request completed");
    Ok(())
}

struct Request { method: String, target: String, headers: Vec<(String, String)>, raw: Vec<u8>, header_end: usize }
impl Request {
    fn header(&self, name: &str) -> Option<&str> { self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()) }
}

fn parse_request(raw: &[u8]) -> Result<Request> {
    let text = std::str::from_utf8(raw)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().context("missing request line")?;
    let mut parts = first.splitn(3, ' ');
    let method = parts.next().context("missing method")?.to_string();
    let target = parts.next().context("missing target")?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() { break; }
        let (key, value) = line.split_once(':').context("invalid header")?;
        headers.push((key.to_string(), value.trim().to_string()));
    }
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").context("missing header terminator")? + 4;
    Ok(Request { method, target, headers, raw: raw.to_vec(), header_end })
}

fn target(request: &Request) -> Result<(&str, u16)> {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = request.target.rsplit_once(':').context("CONNECT needs host:port")?;
        return Ok((host, port.parse()?));
    }
    let uri = request.target.strip_prefix("http://").context("only HTTP absolute-form or CONNECT is supported")?;
    let authority_end = uri.find('/').unwrap_or(uri.len());
    let authority = &uri[..authority_end];
    let host = authority.strip_prefix('[').and_then(|v| v.split_once(']').map(|x| x.0)).unwrap_or(authority.split(':').next().unwrap_or(authority));
    let port = authority.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(80);
    Ok((host, port))
}

fn rewrite_http_request(request: &Request) -> Result<Vec<u8>> {
    let uri = request.target.strip_prefix("http://").context("invalid HTTP target")?;
    let path = uri.find('/').map(|i| &uri[i..]).unwrap_or("/");
    let mut out = format!("{} {} HTTP/1.1\r\n", request.method, path).into_bytes();
    for (key, value) in &request.headers {
        if key.eq_ignore_ascii_case("proxy-authorization") || key.eq_ignore_ascii_case("proxy-connection") || key.eq_ignore_ascii_case("connection") { continue; }
        out.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&request.raw[request.header_end..]);
    Ok(out)
}

async fn serve_admin(address: &str, token: String, metrics: Arc<Metrics>, db: String) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        let token = token.clone();
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_admin(stream, &token, metrics, &db).await { warn!(%error, "admin request failed"); }
        });
    }
}

async fn handle_admin(mut stream: TcpStream, token: &str, metrics: Arc<Metrics>, db: &str) -> Result<()> {
    let started = Instant::now();
    let mut buffer = Vec::with_capacity(2048);
    read_headers(&mut stream, &mut buffer).await?;
    let request = std::str::from_utf8(&buffer)?;
    let mut lines = request.split("\r\n");
    let first = lines.next().context("missing admin request")?;
    let path = first.split_whitespace().nth(1).unwrap_or("/");
    let method = first.split_whitespace().next().unwrap_or("GET");
    let auth = lines.find_map(|line| {
        line.strip_prefix("Authorization: ").or_else(|| line.strip_prefix("authorization: "))
    });
    let expected = format!("Bearer {token}");
    if path != "/" && path != "/healthz" && auth != Some(expected.as_str()) {
        warn!(path, method, reason = "invalid_admin_token", "admin request rejected");
        write_admin_response(&mut stream, "401 Unauthorized", "text/plain", "unauthorized\n").await?;
        return Ok(())
    }
    if method == "POST" && path == "/api/users" {
        let body_start = buffer.windows(4).position(|window| window == b"\r\n\r\n").context("missing admin header terminator")? + 4;
        let content_length = request.lines().find_map(|line| line.strip_prefix("Content-Length: ").or_else(|| line.strip_prefix("content-length: "))).and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
        let mut body = buffer[body_start..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 4096];
            let count = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
            if count == 0 { bail!("admin request body ended early") }
            body.extend_from_slice(&chunk[..count]);
        }
        let form = std::str::from_utf8(&body[..content_length])?;
        let email = form_value(form, "email").context("email is required")?;
        let password = form_value(form, "password").context("password is required")?;
        {
            let conn = Connection::open(db)?;
            init_db(&conn)?;
            conn.execute("INSERT INTO users(email,password_hash) VALUES(?1,?2)", params![email.trim().to_lowercase(), password_hash(&password)?])?;
        }
        write_admin_response(&mut stream, "201 Created", "application/json", "{\"ok\":true}").await?;
        return Ok(())
    }
    match path {
        "/" => write_admin_response(&mut stream, "200 OK", "text/html; charset=utf-8", DASHBOARD_HTML).await?,
        "/healthz" => write_admin_response(&mut stream, "200 OK", "text/plain", "ok\n").await?,
        "/api/metrics" => { let body = metrics.json(); write_admin_response(&mut stream, "200 OK", "application/json", &body).await?; }
        "/api/users" => { let body = { let conn = Connection::open(db)?; init_db(&conn)?; let mut stmt = conn.prepare("SELECT email FROM users WHERE active=1 ORDER BY email")?; let users: Vec<String> = stmt.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?; format!("[{}]", users.iter().map(|email| format!("\"{}\"", email.replace('\\', "\\\\").replace('"', "\\\""))).collect::<Vec<_>>().join(",")) }; write_admin_response(&mut stream, "200 OK", "application/json", &body).await?; }
        "/metrics" => { let body = metrics.prometheus(); write_admin_response(&mut stream, "200 OK", "text/plain; version=0.0.4", &body).await?; }
        _ => write_admin_response(&mut stream, "404 Not Found", "text/plain", "not found\n").await?,
    }
    debug!(path, method, elapsed_ms = started.elapsed().as_millis() as u64, "admin request completed");
    Ok(())
}

fn form_value(form: &str, key: &str) -> Option<String> {
    form.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        if name == key { urlencoding::decode(value).ok().map(|decoded| decoded.into_owned()) } else { None }
    })
}

async fn write_admin_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> Result<()> {
    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
    Ok(())
}

const DASHBOARD_HTML: &str = r#"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Managed Proxy</title><style>body{font:15px system-ui;background:#0f172a;color:#e2e8f0;margin:32px}h1{font-size:24px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}form{display:flex;gap:8px;flex-wrap:wrap}input,button{font:inherit;border-radius:7px;padding:9px 12px;border:1px solid #475569}input{background:#111827;color:#e2e8f0;min-width:220px}button{background:#38bdf8;color:#082f49;border:0;font-weight:700;cursor:pointer}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:24px}.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px}.label{color:#94a3b8;font-size:12px;text-transform:uppercase}.value{font-size:26px;margin-top:8px;font-variant-numeric:tabular-nums}small{color:#94a3b8}#status{color:#fbbf24;margin-top:12px}.panel{background:#111827;border:1px solid #334155;border-radius:10px;padding:16px;margin-top:24px}.panel h2{font-size:16px;margin-top:0}.users{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.user{background:#1e293b;border-radius:99px;padding:7px 11px;color:#cbd5e1}</style></head><body><div class=top><div><h1>Managed Proxy</h1><small>Live data-plane metrics · refresh 2s</small></div><form id=login><input id=token type=password placeholder="Admin token" autocomplete=off><button>Connect</button></form></div><div id=status>Enter the admin token to load metrics.</div><div class=grid id=grid></div><section class=panel><h2>Allow user email</h2><form id=addUser><input id=email type=email placeholder="user@example.com" required><input id=password type=password placeholder="Proxy password" required><button>Add user</button></form><div id=userStatus></div><div class=users id=users></div></section><script>const fields=[['active_connections','Active connections'],['total_connections','Total connections'],['auth_success','Auth success'],['auth_failures','Auth failures'],['auth_cache_hits','Auth cache hits'],['denied_domains','Denied domains'],['upstream_errors','Upstream errors'],['bytes_client_to_upstream','Bytes client → upstream'],['bytes_upstream_to_client','Bytes upstream → client']];const tokenInput=document.getElementById('token'),status=document.getElementById('status'),grid=document.getElementById('grid'),userStatus=document.getElementById('userStatus'),users=document.getElementById('users');tokenInput.value=sessionStorage.getItem('adminToken')||'';const headers=()=>({Authorization:'Bearer '+sessionStorage.getItem('adminToken'),'Content-Type':'application/x-www-form-urlencoded'});document.getElementById('login').onsubmit=e=>{e.preventDefault();sessionStorage.setItem('adminToken',tokenInput.value);refresh()};document.getElementById('addUser').onsubmit=async e=>{e.preventDefault();const body=new URLSearchParams({email:email.value,password:password.value});const r=await fetch('/api/users',{method:'POST',headers:headers(),body});userStatus.textContent=r.ok?'User added; policy reloads within 2 seconds':'Could not add user';if(r.ok){email.value='';password.value='';loadUsers()}};async function refresh(){const token=sessionStorage.getItem('adminToken');if(!token)return;const r=await fetch('/api/metrics',{headers:{Authorization:'Bearer '+token}});if(!r.ok){status.textContent='Authentication failed';return}status.textContent='Connected · updates every 2 seconds';const d=await r.json();grid.innerHTML=fields.map(([k,l])=>`<div class=card><div class=label>${l}</div><div class=value>${Number(d[k]||0).toLocaleString()}</div></div>`).join('');loadUsers()}async function loadUsers(){const r=await fetch('/api/users',{headers:{Authorization:'Bearer '+sessionStorage.getItem('adminToken')}});if(r.ok)users.innerHTML=(await r.json()).map(u=>`<span class=user>${u}</span>`).join('')}refresh();setInterval(refresh,2000)</script></body></html>"#;

async fn read_headers(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<()> {
    loop {
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") { return Ok(()) }
        if buffer.len() >= MAX_HEADER { bail!("request headers too large") }
        let mut chunk = [0u8; 4096];
        let count = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if count == 0 { bail!("client closed connection") }
        buffer.extend_from_slice(&chunk[..count]);
    }
}

fn admin(cli: &Cli, command: &Command) -> Result<()> {
    let conn = Connection::open(&cli.db)?; init_db(&conn)?;
    match command {
        Command::AddUser { email, password } => { conn.execute("INSERT INTO users(email,password_hash) VALUES(?1,?2)", params![email.trim().to_lowercase(), password_hash(password)?])?; println!("user added"); }
        Command::RemoveUser { email } => { conn.execute("DELETE FROM users WHERE email=?1", params![email.trim().to_lowercase()])?; }
        Command::ListUsers => { let mut s = conn.prepare("SELECT email,active FROM users ORDER BY email")?; for r in s.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)?)))? { let row = r?; println!("{} {}", row.0, if row.1 == 1 { "active" } else { "disabled" }); } }
        Command::AddDomain { pattern } => { conn.execute("INSERT INTO domains(pattern) VALUES(?1)", params![normalize_domain(pattern)?])?; println!("domain added"); }
        Command::RemoveDomain { pattern } => { conn.execute("DELETE FROM domains WHERE pattern=?1", params![normalize_domain(pattern)?])?; }
        Command::ListDomains => { let mut s = conn.prepare("SELECT pattern FROM domains ORDER BY pattern")?; for r in s.query_map([], |r| r.get::<_,String>(0))? { println!("{}", r?); } }
        Command::Serve { .. } => unreachable!(),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "managed_proxy=info".into());
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let cli = Cli::parse();
    match &cli.command { Command::Serve { listen, admin_listen } => serve(cli.db.clone(), listen.clone(), admin_listen.clone()).await, _ => admin(&cli, &cli.command) }
}
