use bytes::Bytes;
use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::HeaderMap;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use tracing_appender::rolling;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use tracing_subscriber::layer::SubscriberExt;
#[macro_use]
extern crate tracing;
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Cli {
    /// The http port,default port is 80
    #[arg(default_value_t = 80, short = 'P', long = "port", value_name = "Port")]
    http_port: u32,

    #[arg(
        default_value_t = String::from("http://127.0.0.1:80"),
        short = 'T',
        long = "target_url",
        value_name = "Target Url"
    )]
    target_url: String,
}
#[derive(Debug)]
struct HttpInfo {
    pub request_http_headers: HashMap<String, String>,
    pub url: String,
    pub method: String,
    pub request_http_body: String,
    pub response_http_headers: HashMap<String, String>,
    pub response_http_body: String,
    pub error_message: String,
}
impl HttpInfo {
    pub fn new(
        request_http_headers: HashMap<String, String>,
        request_http_body: String,
        response_http_headers: HashMap<String, String>,
        response_http_body: String,
        error_message: String,
        url: String,
        method: String,
    ) -> Self {
        HttpInfo {
            request_http_headers,
            request_http_body,
            response_http_headers,
            response_http_body,
            error_message,
            url,
            method,
        }
    }
    pub fn empty() -> Self {
        HttpInfo {
            request_http_headers: HashMap::new(),
            request_http_body: "".to_string(),
            response_http_headers: HashMap::new(),
            response_http_body: "".to_string(),
            error_message: "".to_string(),
            url: "".to_string(),
            method: "".to_string(),
        }
    }
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
        Ok(res) => Ok(res),
        Err(err) => {
            http_info.error_message = err.to_string();
            Err(err)
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
    let request_headers = convert(req.headers());
    http_info.request_http_headers = request_headers;

    let (mut req, b) = req.into_parts();
    let collected_bytes = b.collect().await?.to_bytes();
    let bytes_vec = collected_bytes.to_vec();
    let request_body = String::from_utf8(bytes_vec)?;
    http_info.request_http_body = request_body.clone();
    http_info.url = target_url.clone();
    http_info.method = req.method.to_string();
    let new_body = string_to_incoming(request_body.clone());

    req.uri = target_url.parse().unwrap();
    let host = req.uri.host().expect("uri has no host");
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

    let res = sender.send_request(req).await?;
    let (parts, body) = res.into_parts();
    let c = body.collect().await?.to_bytes();
    let response_string = String::from_utf8_lossy(&c);
    let response_header = convert(&parts.headers);
    http_info.response_http_headers = response_header;
    http_info.response_http_body = response_string.to_string();
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
    info!("Listening on http://{}", addr);
    println!("Listening on http://{}", addr);

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
