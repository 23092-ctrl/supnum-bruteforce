use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "SupNum Bruteforce")]
#[command(author = "Cheikh ELghadi")]
#[command(version = "1.0")]
#[command(about = "Multi-service bruteforce tool with advanced HTTP selectors", long_about = None)]
pub struct SupArgs {
    /// Cible (IP ,host ou URL)
    #[arg(short, long)]
    pub target: String,

 
    #[arg(short, long, default_value = "http")]
    pub service: String,

  
    #[arg(short, long)]
    pub wordlist: String,

    /// Nombre de threads (concurrence)
    #[arg(short, long, default_value_t = 10)]
    pub threads: usize,

    /// Port (optionnel, utilise le port par défaut du service sinon)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Message d'erreur à chercher (Succès si absent)
    #[arg(short, long)]
    pub error: Option<String>,

    /// Utilisateur fixe (si non présent dans la wordlist)
    #[arg(long)]
    pub user: Option<String>,

    /// Mot de passe fixe (si non présent dans la wordlist)
    #[arg(long)]
    pub password: Option<String>,

    /// Noms des champs HTML (ex: --names username password)
    #[arg(long, num_args = 2, value_names = ["USER_NAME", "PASS_NAME"])]
    pub names: Option<Vec<String>>,

  
    /// Types des champs HTML (ex: --types text password)
    #[arg(long, num_args = 2, value_names = ["USER_TYPE", "PASS_TYPE"])]
    pub types: Option<Vec<String>>,
    #[arg(long)]
    pub init: bool,
}
