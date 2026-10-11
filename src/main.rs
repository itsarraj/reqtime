use std::time::Duration;

use clap::Parser;
use url::Url;

use reqtime::render::{render_summary, render_waterfall};
use reqtime::timing::follow_redirects;

#[derive(Parser)]
#[command(
    name = "reqtime",
    about = "httpstat for Rust: a real DNS/TCP/TLS/TTFB timing breakdown for one HTTP(S) request"
)]
struct Cli {
    /// URL to request. A missing scheme is treated as http://.
    url: String,

    /// Follow redirects instead of just showing the redirect response.
    #[arg(short = 'L', long)]
    follow: bool,

    /// Maximum redirects to follow.
    #[arg(long, default_value_t = 10)]
    max_redirects: usize,

    /// Connect timeout, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Print response headers for each hop.
    #[arg(short = 'v', long)]
    headers: bool,

    /// Waterfall bar width, in characters.
    #[arg(long, default_value_t = 40)]
    width: usize,
}

fn normalize_url(input: &str) -> Result<Url, String> {
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        format!("http://{input}")
    };
    Url::parse(&with_scheme).map_err(|e| format!("invalid URL '{input}': {e}"))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let url = normalize_url(&cli.url).map_err(|e| anyhow::anyhow!(e))?;

    let hops = follow_redirects(
        &url,
        cli.follow,
        cli.max_redirects,
        Duration::from_secs(cli.timeout),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let last_index = hops.len() - 1;
    for (i, hop) in hops.iter().enumerate() {
        if hops.len() > 1 {
            println!("--- hop {} of {} ---", i + 1, hops.len());
        }
        print!("{}", render_summary(hop));
        if cli.headers {
            for (k, v) in &hop.headers {
                println!("  {k}: {v}");
            }
        }
        println!();
        print!("{}", render_waterfall(hop, cli.width));
        println!();
    }

    let last = &hops[last_index];
    if last.is_redirect() && !cli.follow {
        eprintln!(
            "note: {} is a redirect (to {}); pass -L to follow it",
            last.status,
            last.header("location").unwrap_or("<no Location header>")
        );
    }

    Ok(())
}
