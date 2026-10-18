use hz_core::paths;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let state_dir = paths::state_dir();
    let socket_path = paths::socket_path();
    tracing::info!(
        state_dir = %state_dir.display(),
        socket = %socket_path.display(),
        "hzd starting"
    );
    tokio::select! {
        result = hzd::run(state_dir, socket_path) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("ctrl-c received, hzd shutting down");
            Ok(())
        }
    }
}
