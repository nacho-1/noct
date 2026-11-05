use std::{fmt::Debug, time::Duration};

use noct_models::EventMsg;
use tokio::{sync::mpsc::UnboundedReceiver, task::{JoinError, JoinSet}};

/// Contains structures that map to rows in the db.
pub mod rows;

const FLUSH_INTERVAL: u64 = 2000;
/// Maximum batch size.
///
/// Shouldn't be larger than ClikHouse's max_insert_block_size.
/// See https://clickhouse.com/docs/reference/settings/session-settings/max-insert#max_insert_block_size
const MAX_BATCH_SIZE: usize = 100_000;

pub async fn batcher<F, Fut, T, U>(
    mut rx: UnboundedReceiver<EventMsg<T>>,
    flush_fn: F,
) -> anyhow::Result<()>
where
    F: Fn(Vec<U>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    U: From<T>,
{
    let mut batch: Vec<U> = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(FLUSH_INTERVAL));
    let mut flush_tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();

    loop {
        tokio::select! {
            event = rx.recv() => {
                if event.is_none() {
                    break;
                }
                let event = U::from(event.unwrap().event);
                batch.push(event);
                if batch.len() >= MAX_BATCH_SIZE {
                    let to_flush = std::mem::replace(&mut batch, Vec::new());
                    flush_tasks.spawn(flush_fn(to_flush));
                }
            }

            _ = ticker.tick() => {
                if !batch.is_empty() {
                    let to_flush = std::mem::replace(&mut batch, Vec::new());
                    flush_tasks.spawn(flush_fn(to_flush));
                }
            }

            Some(res) = flush_tasks.join_next(), if !flush_tasks.is_empty() => {
                log_flush_result(res);
            }
        }
    }

    if !batch.is_empty() {
        flush_tasks.spawn(flush_fn(batch));
    }

    while let Some(res) = flush_tasks.join_next().await {
        log_flush_result(res);
    }

    Ok(())
}

fn log_flush_result(res: Result<anyhow::Result<()>, JoinError>) {
    match res {
        Ok(Ok(_)) => tracing::debug!("successful batch flush"),
        Ok(Err(e)) => tracing::error!("batch flush error: {e}"),
        Err(e) => tracing::error!("flush task join error: {e}"),
    }
}

pub async fn log_batch<T>(batch: Vec<T>) -> anyhow::Result<()>
where T: Debug,
{
    tracing::debug!("batch: {:?}", batch);
    Ok(())
}
