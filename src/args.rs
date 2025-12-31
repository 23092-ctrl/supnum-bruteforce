use clap::Parser;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct SupArgs {
    #[arg(short, long)]
    pub target: String,

    #[arg(short, long)]
    pub user: String,

    #[arg(short, long)]
    pub wordlist: String,

    #[arg(short, long)]
    pub service: String,

    #[arg(short, long, default_value_t = 10)]
    pub threads: usize,

    // Nouvel argument pour le port
    #[arg(short, long)]
    pub port: Option<u16>,

    #[arg(short, long)]
    pub error: Option<String>,
}
