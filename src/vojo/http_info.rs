use std::collections::HashMap;

use serde::Serialize;
use serde::Serializer;
#[derive(Debug, Serialize)]
pub struct HttpInfo {
    pub request: Request,
    pub response: Res,
}
#[derive(Debug, Serialize)]

pub struct Request {
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
    pub method: String,
}
impl Request {
    pub fn new(
        headers: HashMap<String, String>,
        body: String,
        url: String,
        method: String,
    ) -> Self {
        Request {
            headers,
            body,
            url,
            method,
        }
    }
}
#[derive(Debug)]

pub struct Res {
    pub response: ResEnum,
}
impl Res {
    pub fn new(response: ResEnum) -> Self {
        Res { response }
    }
}
impl Serialize for Res {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.response {
            ResEnum::Common(common) => common.serialize(serializer),
            ResEnum::Er(err) => serializer.serialize_str(err),
        }
    }
}
#[derive(Debug, Serialize)]

pub enum ResEnum {
    Common(CommonResponse),
    Er(String),
}
#[derive(Debug, Serialize)]

pub struct CommonResponse {
    pub headers: HashMap<String, String>,
    pub body: String,
    pub response_code: i32,
}
impl CommonResponse {
    pub fn new(headers: HashMap<String, String>, body: String, response_code: i32) -> Self {
        CommonResponse {
            headers,
            body,
            response_code,
        }
    }
}
impl HttpInfo {
    pub fn new(request: Request, response: Res) -> Self {
        HttpInfo { request, response }
    }
    pub fn empty() -> Self {
        HttpInfo {
            request: Request::new(HashMap::new(), String::new(), String::new(), String::new()),
            response: Res {
                response: ResEnum::Common(CommonResponse::new(HashMap::new(), String::new(), 0)),
            },
        }
    }
}
