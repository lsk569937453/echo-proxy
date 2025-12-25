use crate::vojo::http_info::ResEnum::Er;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::HeaderMap;
use hyper::StatusCode;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use tracing_appender::rolling;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
mod vojo;
use crate::vojo::http_info::Res;
use crate::vojo::http_info::ResEnum::Common;
use tracing_subscriber::layer::SubscriberExt;
use vojo::http_info::HttpInfo;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate tracing;
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    /// The http port,default port is 80
    #[arg(default_value_t = 80, short = 'P', long = "port", value_name = "Port")]
    http_port: u32,

    #[arg(
        default_value_t = String::from("http://127.0.0.1:8080"),
        short = 'T',
        long = "target_url",
        value_name = "Target Url"
    )]
    target_url: String,
}

fn convert(headers: &HeaderMap<HeaderValue>) -> HashMap<String, String> {
    let mut header_hashmap = HashMap::new();
    for (k, v) in headers {
        let k = k.as_str().to_owned();
        let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
        header_hashmap.entry(k).or_insert_with(|| v);
    }
    header_hashmap
}
async fn echo_with_error(
    req: Request<hyper::body::Incoming>,
    remote_ip: String,
    target_url: String,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let mut http_info = HttpInfo::empty();
    let res = echo(req, remote_ip.clone(), target_url, &mut http_info).await;
    match res {
        Ok(res) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&http_info).unwrap_or_default()
            );
            Ok(res)
        }
        Err(err) => {
            let res_enum = Er(err.to_string());
            http_info.response = Res::new(res_enum);
            println!(
                "{}",
                serde_json::to_string_pretty(&http_info).unwrap_or_default()
            );
            let body = string_to_incoming(err.to_string());
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(body)
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(response)
        }
    }
}
fn string_to_incoming(s: String) -> Full<Bytes> {
    let bytes = Bytes::from(s);

    Full::<Bytes>::from(bytes)
}
#[instrument]
async fn echo(
    req: Request<hyper::body::Incoming>,
    remote_ip: String,
    target_url: String,
    http_info: &mut HttpInfo,
) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let target_uri_string = format!(
        "{}{}",
        target_url,
        uri.path_and_query().map(|x| x.as_str()).unwrap_or("/")
    );
    println!("target url is: {}", target_uri_string);
    let request_headers = convert(req.headers());
    http_info.request.headers = request_headers;

    let (mut req, b) = req.into_parts();
    let collected_bytes = b.collect().await?.to_bytes();
    let bytes_vec = collected_bytes.to_vec();
    let request_body = String::from_utf8(bytes_vec)?;
    http_info.request.body = request_body.clone();
    http_info.request.url = uri.to_string();
    http_info.request.method = req.method.to_string();

    let new_body = string_to_incoming(request_body.clone());
    req.headers
        .append("host", HeaderValue::from_static("httpbin.org"));
    req.uri = target_uri_string.parse().unwrap_or_default();
    let host = req.uri.host().unwrap_or_default();
    let port = req.uri.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    let client_stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(client_stream);
    let req = Request::from_parts(req, new_body);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });
    let res = sender
        .send_request(req)
        .await
        .map_err(|e| anyhow!(e.to_string()))?;

    let status_code = res.status().as_u16();
    println!("status code is: {}", status_code);
    let (parts, body) = res.into_parts();
    let c = body.collect().await?.to_bytes();
    let response_string = String::from_utf8_lossy(&c).to_string();
    let response_header = convert(&parts.headers);
    let common_response =
        vojo::http_info::CommonResponse::new(response_header, response_string, status_code as i32);
    let response = Res::new(Common(common_response));
    http_info.response = response;
    let body = Full::new(c);
    let res = Response::from_parts(parts, body);
    Ok(res)
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
fn setup_logger() -> Result<(), anyhow::Error> {
    let app_file = rolling::daily("./logs", "access.log");

    let file_layer = tracing_subscriber::fmt::Layer::new()
        .with_target(true)
        .with_ansi(false)
        .with_writer(app_file)
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
    let console_layer = tracing_subscriber::fmt::Layer::new()
        .with_target(true)
        .with_ansi(true) // Enable ANSI color codes for console output
        .with_writer(std::io::stdout) // Log to stdout (console)
        .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG); //
    tracing_subscriber::registry()
        .with(file_layer)
        .with(console_layer)
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .init();
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    setup_logger()?;
    let cli: Cli = Cli::parse();
    let port = cli.http_port;
    let addr = format!(r#"0.0.0.0:{port}"#);
    let target_url = cli.target_url;
    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on http://{},target url:{}", addr, target_url);
    // println!("Listening on http://{},target url:{}", addr, target_url);

    loop {
        let (stream, addr) = listener.accept().await?;
        let addr_str = addr.to_string();
        let addr_str_clone = addr_str.clone();
        let target_url_cloned = target_url.clone();
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(
                    io,
                    service_fn(move |req: Request<Incoming>| {
                        echo_with_error(req, addr_str_clone.clone(), target_url_cloned.clone())
                    }),
                )
                .await
            {
                // info!("Error serving connection: {:?},addr is:{:}", err, addr_str);
            }
        });
    }
}
