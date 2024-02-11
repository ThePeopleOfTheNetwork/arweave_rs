//! Populates the `BlockIndex` from an arweave peer using the `/block_index`
//! endpoint.
use arweave_rs_types::*;
use color_eyre::eyre::eyre;
use eyre::{Report, Result};
use futures::future::try_join_all;
use reqwest::{header, Client as ReqwestClient, StatusCode};
use serde_derive::{Deserialize, Serialize};
use std::time::Duration;

// This is the format of the JSON
// {
//   "tx_root" : "FDQNxgnKyW3ugAPJNipcA8jIplL0Jw8yD7j1dm3iViI",
//   "weave_size" : "152674506940662",
//   "hash" : "rRJ-5cTFVeTxtQDlTJgITpnDFfU58Fi2WYy4jNvBY7xQPK9HpgrEdacpUj1HbHAh"
// }

/// Stores the deserialized JSON block index data returned by the the peers
/// `/block_index/<start_height>/<end_height>` endpoint.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BlockIndexJson {
    pub tx_root: String,
    pub weave_size: String,
    pub hash: String,
}

/// The primary worker function for retrieving Block Indexes from the Arweave
/// network.
pub async fn request_indexes(
    node_url: &str,
    start_block_heights: &[(u64, u64)],
) -> Result<Vec<Vec<BlockIndexJson>>> {
    let client = ReqwestClient::new();
    let requests = start_block_heights.iter().map(|bh| {
        let (start_block_height, num_indexes) = bh;
        let end_block_height = start_block_height + num_indexes;
        request_block_index_jsons(node_url, *start_block_height, end_block_height, &client)
    });

    // Concurrently execute the requests
    let results = try_join_all(requests).await;
    match results {
        Ok(res) => Ok(res),
        Err(e) => Err(eyre!(e)),
    }
}

/// Request the block index data from the peer. Support a `max_retries` count
///  with a delay between retry attempts for each block index page.
async fn request_block_index_jsons(
    node_url: &str,
    start_block_height: u64,
    end_block_height: u64,
    client: &ReqwestClient,
) -> Result<Vec<BlockIndexJson>> {
    let url = format!("{node_url}/block_index/{start_block_height}/{end_block_height}");
    let max_retries = 3;
    let mut retry_count = 0;
    let mut last_error: Option<Report>;

    let result: Result<Vec<BlockIndexJson>> = loop {
        // Make the async HTTP request and await the response
        // include the x-block-format header so we'll get weaveSize and tx_root
        // in our response.
        let result = client
            .get(&url)
            .header(header::HeaderName::from_static("x-block-format"), "1")
            .send()
            .await;

        match result {
            Ok(res) => {
                if res.status() == StatusCode::OK {
                    let parsed = res
                        .json::<Vec<BlockIndexJson>>()
                        .await
                        .expect("JSON should be parsable to [BlockIndexJson]");
                    break Ok(parsed);
                } else {
                    last_error = Some(eyre!("Last HTTP Status code was {}", res.status()));
                }
                retry_count += 1;
            }
            Err(err) => {
                // error trying to connect: dns error: failed to lookup address information: nodename nor servername provided, or not known
                println!("Request to {} failed with error: {}", url, err);
                retry_count += 1;
                last_error = Some(eyre!(err));
            }
        }

        if retry_count == max_retries {
            break Err(last_error.expect("last_error should contain the most recent error"));
        }
        println!("Retrying... {}", url);
        tokio::time::sleep(Duration::from_secs(1)).await; // Add a delay before retrying
    };

    match result {
        Ok(mut res) => {
            res.reverse();
            Ok(res)
        }
        Err(e) => Err(eyre!(e)),
    }
}

/// Synchronously get the current block height from <https://https://arweave.net/block/current>.
pub fn current_block_height() -> u64 {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(current_block_header()).unwrap();
    result.height
}

/// Asynchronously get the current block height from <https://https://arweave.net/block/current>.
pub async fn current_block_height_async() -> u64 {
    let result = current_block_header().await.unwrap();
    result.height
}

/// Get the current block header from <https://https://arweave.net/block/current> 
/// TODO: Make this configurable so that it can pull from any peer.
async fn current_block_header() -> Result<ArweaveBlockHeader> {
    // Use reqwest to query the current block header data
    let client = ReqwestClient::new();
    let url = format!("https://arweave.net/block/{}", "current");

    // Can get this error here and panic
    // Error:
    // 0: HTTP status client error (429 Too Many Requests) for url (https://arweave.net/block/current)
    let res = client.get(url).send().await?.error_for_status()?;

    if res.status() == StatusCode::OK {
        let current_block_header = res.json::<ArweaveBlockHeader>().await?;
        Ok(current_block_header)
    } else {
        Err(eyre!("HTTP request returned Status Code {}", res.status()))
    }
}
