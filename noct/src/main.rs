use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    noct::init_tracing();

    match noct::run().await {
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
