#![cfg(test)]

use reqwest::StatusCode;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// 测试专用 HTTP 捕获结果，集中放到独立模块后，后续新增 API 测试可以直接复用，
/// 不需要在每个测试文件里重复维护一套 socket 读写逻辑。
#[derive(Debug)]
pub(crate) struct CapturedRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) json_body: Value,
}

pub(crate) struct MockHttpServer {
    base_url: String,
    receiver: mpsc::Receiver<CapturedRequest>,
    handle: thread::JoinHandle<()>,
}

impl MockHttpServer {
    pub(crate) fn serve_once(status: u16, body: Value) -> Self {
        let body_text = body.to_string();
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status_line(status),
            body_text.len(),
            body_text
        );
        Self::serve_once_raw(response)
    }

    pub(crate) fn serve_once_raw(response: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let captured = read_request(&mut stream);
            sender.send(captured).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        Self {
            base_url: format!("http://{}", address),
            receiver,
            handle,
        }
    }

    pub(crate) fn base_url(&self) -> String {
        self.base_url.clone()
    }

    pub(crate) fn finish(self) -> CapturedRequest {
        let request = self.receiver.recv().unwrap();
        self.handle.join().unwrap();
        request
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end;
    loop {
        let bytes_read = stream.read(&mut chunk).unwrap();
        buffer.extend_from_slice(&chunk[..bytes_read]);
        if let Some(index) = find_header_end(&buffer) {
            header_end = index;
            break;
        }
    }

    let header_text = String::from_utf8(buffer[..header_end].to_vec()).unwrap();
    let content_length = parse_content_length(&header_text);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let bytes_read = stream.read(&mut chunk).unwrap();
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }

    let request_line = header_text.lines().next().unwrap();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_owned();
    let path = parts.next().unwrap().to_owned();
    let body = &buffer[body_start..body_start + content_length];
    let json_body = serde_json::from_slice(body).unwrap();

    CapturedRequest {
        method,
        path,
        json_body,
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let mut parts = line.splitn(2, ':');
            let name = parts.next()?.trim();
            let value = parts.next()?.trim();
            if name.eq_ignore_ascii_case("content-length") {
                value.parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn status_line(status: u16) -> &'static str {
    match StatusCode::from_u16(status).unwrap() {
        StatusCode::OK => "200 OK",
        StatusCode::SERVICE_UNAVAILABLE => "503 Service Unavailable",
        _ => "500 Internal Server Error",
    }
}
