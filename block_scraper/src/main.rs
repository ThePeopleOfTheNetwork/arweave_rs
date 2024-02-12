use arweave_rs_indexes::*;
use arweave_rs_randomx::{create_randomx_vm, RandomXMode, RandomXVM};
use arweave_rs_types::{consensus::*, *};
use arweave_rs_validator::pre_validate_block;
use color_eyre::eyre::eyre;
use eyre::{Report, Result};
use futures::future::try_join_all;
use reqwest::{Client as ReqwestClient, StatusCode};
use std::{time::{Duration, Instant}, io::{self, Write}};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let client = ReqwestClient::new();
    let url = format!("https://arweave.net/block/{}", "current");

    // Can get this error here and panic
    // Error:
    // 0: HTTP status client error (429 Too Many Requests) for url (https://arweave.net/block/current)
    let res = client.get(url).send().await?.error_for_status()?;

    #[allow(unused_assignments)]
    let mut current_block_height: u64 = 0;

    if res.status() == StatusCode::OK {
        let block_header_res = res.json::<ArweaveBlockHeader>().await;
        match block_header_res {
            Ok(current_block_header) => {
                current_block_height = current_block_header.height;
            }
            Err(err) => {
                println!("Error getting current block {err}");
                return Err(eyre!(err));
            }
        }
        //println!("{}",serde_json::to_string_pretty(&current_block_header).unwrap());
    } else {
        return Err(eyre!("HTTP request returned Status Code {}", res.status()));
    }

    // Initialize the block_index, which may mean polling new blocks from arweave
    let block_index: BlockIndex = BlockIndex::new();
    let init_block_index = Instant::now();
    let block_index = block_index.init().await.expect("block index to initialize");
    let end_init_block_index = init_block_index.elapsed();
    println!("BlockIndex initialization: {:?}", end_init_block_index);

    // Initialize the randomx vm for FastHashing (consumes more memory and takes
    // longer to initialize but produces hashes significantly faster)
    let start_vm = Instant::now();
    let vm = create_randomx_vm(RandomXMode::FastHashing, RANDOMX_PACKING_KEY);
    let end_vm = start_vm.elapsed();
    println!("RandomX VM initialization: {:?}", end_vm);

    let batch_size = 100;
    let mut end_height = current_block_height;
    process_block_header_batch(&block_index, &vm, batch_size, end_height).await?;

    let mut should_continue = true;

    while should_continue {
        println!("Validate the next 100 headers? [Y/n]:");
        // Flush stdout to ensure the message is displayed before blocking for input
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                
                match input.trim().to_uppercase().as_str() {
                    "" => {
                        should_continue = true;
                    },
                    "Y" => {
                        should_continue = true;
                    }
                    _ => {
                        should_continue = false;
                    }
                }
            },
            Err(error) => println!("Error reading from stdin: {}", error),
        }
        println!("should_continue: {should_continue}");
        if should_continue {
            end_height -= batch_size as u64 - 1;
            process_block_header_batch(&block_index, &vm, batch_size, end_height).await?;
        }
    }

    Ok(())
}

pub async fn process_block_header_batch(
    block_index: &BlockIndex<Initialized>,
    vm: &RandomXVM,
    batch_size: usize,
    end_height: u64,
) -> Result<()> {
    let mut batch: Vec<u64> = vec![];
    let start_block_height = end_height - batch_size as u64;

    for index in (start_block_height..end_height).rev() {
        let block_height = index;

        batch.push(block_height);

        // Is it time to make the batch request?
        if batch.len() == batch_size || index == start_block_height {
            // Await completion of the reqwest batch
            let mut res = get_block_headers(&batch)
                .await
                .expect("all block headers to be retrieved and parsed");

            // Sort the headers
            res.sort_by_key(|bh| bh.height);
            res.reverse();

            // Windows iterator iterates a set using sliding windows, in this case, of size 2
            for window in res.windows(2) {
                let current = &window[0];
                let previous = &window[1];

                let start = Instant::now();
                let solution_hash =
                    pre_validate_block(current, previous, block_index, Some(vm))?;
                // Get the elapsed time for validating the block
                let duration = start.elapsed(); 

                // Encode the computed solution_hash and the observed one.
                let encoded = base64_url::encode(&solution_hash);
                let encoded2 = base64_url::encode(&current.hash);

                // Compare them, printing out the correct emoji if they match or not
                if encoded == encoded2 {
                    println!("✅{} {} {:?}", current.height, encoded, duration);
                } else {
                    println!(
                        "❌{} {} {} {:?}",
                        current.height, encoded, encoded2, duration
                    );
                }
            }

            // TODO: Inspect the results to find blocks where the entropy reset happens on the first or last step
            // #[allow(unused_variables)]
            // for header in res {
            // The first step of the next block is a reset
            // let remainder = (header.nonce_limiter_info.global_step_number + 1) as f64 / NONCE_LIMITER_RESET_FREQUENCY as f64;
            // if remainder.fract() == 0.0 {
            //     println!("next height is reset: {}", header.height);
            // }

            println!(
                "✅ Finished validating headers! {}/{}!",
                batch.len(),
                batch.len()
            );

            // Reset the batch, we're going again.
            batch.clear();
        }
    }

    Ok(())
}

pub async fn request_block_header_with_retry(
    block_height: &u64,
    url: String,
    client2: &ReqwestClient,
) -> Result<ArweaveBlockHeader, Report> {
    let url2 = url;
    let mut retry_count = 0;
    let max_retries = 3;
    let mut last_error: Option<Report>;

    let result: Result<ArweaveBlockHeader, Report> = loop {
        // Make the async HTTP request and await the response
        let result = client2.get(&url2).send().await; // retry logic?

        match result {
            Ok(res) => {
                if res.status() == StatusCode::OK {
                    let parsed_res = res.json::<ArweaveBlockHeader>().await;
                    match parsed_res {
                        Ok(parsed) => break Ok(parsed),
                        Err(err) => {
                            println!("{:?} {url2}", err);
                            break Err(eyre!(err));
                        }
                    }
                    // .expect(
                    //     format!("JSON should be parsable to BlockHeaderData {url2}").as_str(),
                    // );
                    // Possible error(s) here
                    // reqwest::Error { kind: Body, source: hyper::Error(Body, Error { kind: Io(Kind(ConnectionReset)) }) }
                    //println!("Got JSON for block_height: {}", bh);
                } else {
                    last_error = Some(eyre!("Reqwest HTTP Status code was {}", res.status()));
                }
                retry_count += 1;
            }
            Err(err) => {
                // error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known
                println!("Request to {} failed with error: {}", url2, err);
                retry_count += 1;
                last_error = Some(eyre!(err));
            }
        }

        if retry_count == max_retries {
            break Err(last_error.expect("last_error should contain the most recent error"));
        }

        println!("Retrying... {}", block_height);
        tokio::time::sleep(Duration::from_secs(1)).await; // Add a delay before retrying
    };
    result
}

pub async fn get_block_headers(block_heights: &[u64]) -> Result<Vec<ArweaveBlockHeader>> {
    let mut complete_count = 0;
    let client2 = ReqwestClient::new();
    let requests = block_heights.iter().map(|bh| {
        let url = format!("https://arweave.net/block/height/{}", bh);
        let results = request_block_header_with_retry(bh, url, &client2);
        complete_count += 1;
        results
    });

    // Execute the requests concurrently
    let results = try_join_all(requests).await;
    match results {
        Ok(res) => Ok(res),
        Err(e) => Err(eyre!(e)),
    }
}
