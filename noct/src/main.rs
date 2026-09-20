use std::process::ExitCode;

use clap::Parser;
use noct::Opts;

#[tokio::main]
async fn main() -> ExitCode {
    let opts = Opts::parse();

    noct::init_tracing();

    match noct::run(opts).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(
                error.msg = %e,
                error.error_chain = ?e,
                "Shutting down due to error"
            );
            ExitCode::FAILURE
        }
    }
}
