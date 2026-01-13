use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "SupNum Bruteforce")]
#[command(author = "Cheikh ELghadi")]
#[command(version = "1.0")]
#[command(about = "Multi-service bruteforce tool with advanced HTTP selectors", long_about = None)]
pub struct SupArgs {

    #[arg(short, long)]
    pub target: String,

    #[arg(short, long, default_value = "http")]
    pub service: String,

    
  #[arg(
        short, 
        long, 
        num_args = 1..=2, // <--- C'est ici le changement important
        value_names = ["USERS", "PASSWORDS"],
        help = "1 fichier (combo/split) ou 2 fichiers (matrix attack)"
    )]
    pub wordlist: Vec<String>,

    #[arg( long, default_value_t = 10)]
    pub threads: usize,

    #[arg(long)]
    pub port: Option<u16>,

  
    #[arg(short, long)]
    pub error: Option<String>,

    #[arg(short,long)]
    pub user: Option<String>,

    #[arg(short,long)]
    pub password: Option<String>,

    
    #[arg(short,long, num_args = 2, value_names = ["USER_NAME", "PASS_NAME"])]
    pub names: Option<Vec<String>>,

    #[arg(long, num_args = 2, value_names = ["USER_TYPE", "PASS_TYPE"])]
    pub types: Option<Vec<String>>,
    #[arg(long)]
    pub init: bool,
    #[arg(short, long)]
    pub delay: Option<u64>,
}
