use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::Client;
use serde_json::Value;
use tokio::sync::Semaphore;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Runs real HTTP load; execute explicitly with cargo test --test performance -- --ignored --nocapture"]
async fn auth_token_rps_baseline() {
    let total_requests = read_usize_env("PERF_TOTAL_REQUESTS", 1000);
    let concurrency = read_usize_env("PERF_CONCURRENCY", 20);
    let min_rps = read_u64_env("PERF_MIN_RPS", 100);
    let hold_seconds = read_u64_env("PERF_HOLD_SECONDS", 0);
    let secret = std::env::var("PERF_TOKEN_SIGNING_SECRET")
        .unwrap_or_else(|_| "perf-test-secret".to_owned());

    let port = pick_free_port();
    let child = spawn_server(port, &secret);

    let base_url = format!("http://127.0.0.1:{port}");
    println!(
        "Perf server is running: pid={} base_url={} metrics={}/metrics",
        child.id(),
        base_url,
        base_url
    );
    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build reqwest client");

    wait_for_health(&client, &base_url)
        .await
        .expect("server did not become healthy");

    let started = Instant::now();
    let ok = run_parallel_auth_token_load(
        client.clone(),
        base_url.clone(),
        total_requests,
        concurrency,
    )
    .await;
    let elapsed = started.elapsed().as_secs_f64();
    let rps = ok as f64 / elapsed;

    println!(
        "auth_token_rps_baseline: ok={ok}/{total_requests}, elapsed={elapsed:.2}s, rps={rps:.2}, concurrency={concurrency}"
    );
    assert_eq!(ok, total_requests, "not all requests succeeded");
    assert!(
        rps >= min_rps as f64,
        "RPS below threshold: actual={rps:.2}, expected>={min_rps}"
    );

    if hold_seconds > 0 {
        println!(
            "Holding test process for {}s so you can check metrics at {}/metrics",
            hold_seconds, base_url
        );
        tokio::time::sleep(Duration::from_secs(hold_seconds)).await;
    }

    // Intentionally keep server running until test process exits.
    std::mem::forget(child);
}

async fn run_parallel_auth_token_load(
    client: Client,
    base_url: String,
    total_requests: usize,
    concurrency: usize,
) -> usize {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = Vec::with_capacity(total_requests);

    for i in 0..total_requests {
        let client = client.clone();
        let url = format!("{base_url}/auth/token");
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore closed");
            let response = client
                .post(url)
                .json(&serde_json::json!({ "subject": format!("perf-user-{i}") }))
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let body = resp.json::<Value>().await.ok();
                    body.and_then(|v| v.get("id_token").cloned())
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .is_some()
                }
                _ => false,
            }
        }));
    }

    let mut ok = 0usize;
    for task in tasks {
        if task.await.unwrap_or(false) {
            ok += 1;
        }
    }
    ok
}

async fn wait_for_health(client: &Client, base_url: &str) -> Result<(), ()> {
    let url = format!("{base_url}/health");
    for _ in 0..60 {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(())
}

fn spawn_server(port: u16, secret: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_auth-emulator"))
        .env("BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("TOKEN_SIGNING_SECRET", secret)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn auth-emulator process")
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve free port");
    listener.local_addr().expect("local_addr failed").port()
}

fn read_usize_env(name: &str, default_value: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_value)
}

fn read_u64_env(name: &str, default_value: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_value)
}
