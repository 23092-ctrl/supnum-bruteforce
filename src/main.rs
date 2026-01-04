mod args;
mod header;

use args::SupArgs;
use clap::Parser;
use sqlx::{Connection, MySqlConnection};
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
use tokio::net::TcpStream;

async fn detect_service(target: &str, port: u16) -> String {
    let addr = format!("{}:{}", target, port);
    let stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await;

    match stream {
        Ok(Ok(mut s)) => {
            let mut buffer = [0; 256];
            if let Ok(n) = timeout(Duration::from_millis(1500), s.read(&mut buffer)).await.unwrap_or(Ok(0)) {
                let resp = String::from_utf8_lossy(&buffer[..n]).to_uppercase();
                if resp.contains("SSH") { return "ssh".to_string(); }
                if resp.contains("220") && resp.contains("FTP") { return "ftp".to_string(); }
                if resp.contains("220") && (resp.contains("SMTP") || resp.contains("ESMTP")) { return "smtp".to_string(); }
                if resp.contains("MYSQL") || (n > 5 && buffer[4] == 0x0a) { return "mysql".to_string(); }
            }
            let _ = s.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
            if let Ok(n) = timeout(Duration::from_millis(1000), s.read(&mut buffer)).await.unwrap_or(Ok(0)) {
                let resp = String::from_utf8_lossy(&buffer[..n]).to_uppercase();
                if resp.contains("HTTP") || resp.contains("HTML") { return "http".to_string(); }
            }
            "unknown".to_string()
        }
        _ => "closed".to_string(),
    }
}

// --- UTILITAIRES RÉSEAU -
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
    
   
    match timeout(Duration::from_secs(3), MySqlConnection::connect(&url)).await {
        Ok(Ok(mut conn)) => {
          
            let _ = conn.close().await; 
            true
        }
        _ => false, 
    }
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


fn find_name_by_type(html: &str, target_type: &str) -> Option<String> {
    
    let pattern = format!("type=\"{}\"", target_type);
    if let Some(pos) = html.find(&pattern) {
     
        let start_of_tag = html[..pos].rfind('<').unwrap_or(0);
        let end_of_tag = html[pos..].find('>').unwrap_or(html.len() - pos) + pos;
        let tag_content = &html[start_of_tag..end_of_tag];

        if let Some(name_pos) = tag_content.find("name=\"") {
            let start_name = name_pos + 6;
            if let Some(end_name) = tag_content[start_name..].find('\"') {
                return Some(tag_content[start_name..start_name+end_name].to_string());
            }
        }
    }
    None
}



 // --- MODULES DE CONNEXION ---
async fn attempt_http(
    client: &Client, 
    target: &str, 
    port: u16, 
    user: &str, 
    pass: &str, 
    error_msg: &Option<String>,
    u_selector: &str, 
    p_selector: &str  
) -> bool {
    
    let url = if target.starts_with("https://") || target.starts_with("http://") {
      
        target.to_string()
    } else {
       
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };

    let mut final_u_field = u_selector.to_string();
    let mut final_p_field = p_selector.to_string();
    let mut use_get = false;

  
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(html) = resp.text().await {
            let html_low = html.to_lowercase();
            if html_low.contains("method=\"get\"") || html_low.contains("method='get'") {
                use_get = true;
            }

            if let Some(found_u) = find_name_by_type(&html, u_selector) {
                final_u_field = found_u;
            }
            if let Some(found_p) = find_name_by_type(&html, p_selector) {
                final_p_field = found_p;
            }
        }
    }

    // --- ÉTAPE B : PARAMÈTRES ---
    let params = [
        (final_u_field.trim(), user.trim()), 
        (final_p_field.trim(), pass.trim())
    ];

    // --- ÉTAPE C : ENVOI ---
    let request = if use_get {
        client.get(&url).query(&params)
    } else {
        client.post(&url).form(&params)
    };

    let res = request.send().await;

    if let Ok(r) = res {
        // Succès si redirection (301, 302)
        if r.status().is_redirection() { return true; }
        
        
        if let Some(msg) = error_msg {
            if let Ok(text) = r.text().await {
                if !text.to_lowercase().contains(&msg.to_lowercase()) { return true; }
            }
        }
    }
    false
}

async fn attempt_vnc(host: &str, port: u16, pass: &str) -> bool {
    let addr = format!("{}:{}", host, port);
    
    // Tentative de connexion TCP
    let mut stream = match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    let mut buf = [0; 12];
    // 1. Lire la version du protocole (ex: RFB 003.008)
    if timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await.is_err() {
        return false;
    }

    // 2. Répondre avec la même version
    if stream.write_all(&buf).await.is_err() {
        return false;
    }

    // 3. Recevoir les types de sécurité
    let mut sec_types = [0u8; 1];
    if stream.read_exact(&mut sec_types).await.is_err() {
        return false;
    }

   
    true 
}
// --- MOTEUR PRINCIPAL ---


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    header::show("Cheikh ELghadi", "https://github.com/23092-ctrl");
    let args = SupArgs::parse();

    // --- 1. FILTRAGE ET PARSING DE LA CIBLE ---
    let input_target = args.target.trim();
    
    let temp_target = if !input_target.contains("://") {
        format!("{}://{}", args.service.to_lowercase(), input_target)
    } else {
        input_target.to_string()
    };

    let parsed_url = reqwest::Url::parse(&temp_target)
        .expect("[-] Format de cible invalide.");

    // RÉCUPÉRATION DE L'HÔTE (Cas général : IP ou Domaine)
    let host_only = parsed_url.host_str().ok_or("Impossible d'extraire l'hôte")?.to_string();

    
    let t_service_lower = if input_target.contains("://") {
        parsed_url.scheme().to_lowercase()
    } else {
        args.service.to_lowercase()
    };

    // DÉTERMINATION DU PORT (Priorité : 1. Argument --port | 2. Port dans l'URL | 3. Défaut du service)
    let port_to_use = args.port
        .or(parsed_url.port())
        .unwrap_or(match t_service_lower.as_str() {
            "ssh" => 22, "ftp" => 21, "smb" => 445, "mysql" => 3306,
            "smtp" => 25, "pop3" => 110, "imap" => 143, "https" => 443,
            "rdp" => 3389, "telnet" => 23, "mongodb" => 27017, "postgres" => 5432,
            "vnc" => 5900,
            _ => 80,
            
        });

    // --- 2. DÉTECTION RÉELLE DU SERVICE (BANNER GRABBING) ---
   
    let detected = detect_service(&host_only, port_to_use).await;
    if detected == "closed" {
        println!("{} Port {} fermé sur {}.", "[!]".red(), port_to_use, host_only);
        return Ok(());
    } 

    // --- 3. INITIALISATION ---
    let success_found = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let client = Arc::new(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?);


let mut u_field = "username".to_string();
let mut p_field = "password".to_string();

// 2. Priorité aux NOMS (si --names est utilisé)
if let Some(ref names) = args.names {
    u_field = names[0].clone();
    p_field = names[1].clone();
} 

else if let Some(ref types) = args.types {
    
    if let Ok(resp) = client.get(input_target).send().await {
        if let Ok(html) = resp.text().await {
            if let Some(name) = find_name_by_type(&html, &types[0]) {
                u_field = name;
            }
            if let Some(name) = find_name_by_type(&html, &types[1]) {
                p_field = name;
            }
        }
    }
}

 
    // --- 4. LECTURE DU DICTIONNAIRE ---
    let f_dict = File::open(&args.wordlist).await?;
    let mut lines = BufReader::new(f_dict).lines();
    let mut set = JoinSet::new();

    // --- AJOUT DE LA LOGIQUE DE CACHE ---
    let cache_file = ".supnum_cache";
    let mut current_line = 0; // On initialise le compteur ici

    // Gestion du flag --init (supprime le cache)
    if args.init {
        let _ = std::fs::remove_file(cache_file);
        println!("{} Cache initialisé.", "[*]".yellow());
    }

    // Lecture de la position de reprise
    let mut start_line = 0;
    if let Ok(content) = std::fs::read_to_string(cache_file) {
        start_line = content.trim().parse::<usize>().unwrap_or(0);
        if start_line > 0 {
            println!("{} Reprise à la ligne : {}", "[*]".cyan(), start_line);
        }
    }

    println!("[*] Cible   : {}", host_only.cyan());
    
    println!("------------------------------------------------------------");

    // --- 5. BOUCLE PRINCIPALE ---
    let t_delay = args.delay; 
    while let Ok(Some(line)) = lines.next_line().await {
        current_line += 1; 

        if current_line <= start_line {
            continue; 
        }

        let raw_line = line.trim().to_string();
        if raw_line.is_empty() { continue; }

        // Sauvegarde automatique tous les 100 essais
        if current_line % 100 == 0 {
            let _ = std::fs::write(cache_file, current_line.to_string());
        }

        // ... (Le reste de ton code de parsing et spawn reste identique) ...
        let (u, p) = if raw_line.contains(':') {
            let parts: Vec<&str> = raw_line.splitn(2, ':').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else if let Some(ref fixed_user) = args.user {
            (fixed_user.clone(), raw_line)
        } else if let Some(ref fixed_pass) = args.password {
            (raw_line, fixed_pass.clone())
        } else {
            (raw_line.clone(), raw_line.clone())
        };

        // Clonage des variables pour le thread
        let t_u = u; let t_p = p;
        let t_host = host_only.clone();
        let t_url = input_target.to_string(); 
        let t_service = t_service_lower.clone();
        let t_client = Arc::clone(&client);
        let t_success = Arc::clone(&success_found);
        let t_error = args.error.clone();
        let (t_uf, t_pf) = (u_field.clone(), p_field.clone());
        let t_port = port_to_use;

        let permit = Arc::clone(&semaphore).acquire_owned().await?;

        set.spawn(async move {
            let _permit = permit;
            if t_success.load(Ordering::SeqCst) { return; }
            if let Some(ms) = t_delay {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
            let ok = match t_service.as_str() {
                "ssh"  => attempt_ssh(&t_host, t_port, &t_u, &t_p).await,
                "http" | "https" => attempt_http(&t_client, &t_url, t_port, &t_u, &t_p, &t_error, &t_uf, &t_pf).await,
                "ftp"  => {
                    let addr = format!("{}:{}", t_host, t_port);
                    if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(4), AsyncFtpStream::connect(addr)).await {
                        let res = ftp.login(&t_u, &t_p).await.is_ok();
                        let _ = ftp.quit().await; res
                    } else { false }
                },
                "mysql"    => attempt_mysql(&t_host, t_port, &t_u, &t_p).await,
                "postgres" => attempt_postgres(&t_host, t_port, &t_u, &t_p).await,
                "mongodb"  => attempt_mongodb(&t_host, t_port, &t_u, &t_p).await,
                "smb"      => attempt_smb(&t_host, &t_u, &t_p).await,
                "smtp"     => attempt_smtp(&t_host, t_port, &t_u, &t_p).await,
                "pop3"     => attempt_pop3(&t_host, t_port, &t_u, &t_p).await,
                "imap"     => attempt_imap(&t_host, t_port, &t_u, &t_p).await,
                "ldap"     => attempt_ldap(&t_host, t_port, &t_u, &t_p).await,
                "telnet"   => attempt_telnet(&t_host, t_port, &t_u, &t_p).await,
                "rdp"      => attempt_rdp(&t_host, t_port, &t_u, &t_p).await,
                "vnc"      => attempt_vnc(&t_host, t_port, &t_p).await,
                _ => false,
            };

            if ok && !t_success.swap(true, Ordering::SeqCst) {
                let _ = std::fs::remove_file(".supnum_cache");
                println!("\n\n{}", "====================================================".green().bold());
                println!("{} SUCCÈS TROUVÉ !", "[+]".green().bold());
                println!("{} UTILISATEUR : {}", " >".cyan(), t_u.bright_white().bold());
                println!("{} MOT DE PASSE : {}", " >".cyan(), t_p.bright_yellow().bold());
                println!("{}", "====================================================".green().bold());
                std::process::exit(0);
            }
        });
    }

    while let Some(_) = set.join_next().await {}
    Ok(())
}
