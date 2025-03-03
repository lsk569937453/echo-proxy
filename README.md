1.https://youtube.com/shorts/1MFvISGFKxM?feature=share

# Echo Proxy

## Introduction

Echo Proxy is a lightweight HTTP proxy tool developed in Rust, designed to inspect and debug HTTP request and response parameters. It serves as a valuable resource for developers during the development and testing phases, enabling them to capture and analyze HTTP traffic passing through the proxy. This ensures that the communication between clients and servers adheres to expected standards and facilitates the identification of potential issues.

## How It Works

Echo Proxy operates by intercepting HTTP traffic between the client and the target server. It logs the details of each request and response, providing insights into the data being transmitted. This functionality is particularly useful for debugging and verifying the correctness of HTTP interactions.
To see Echo Proxy in action, check out this [video demonstration](https://youtube.com/shorts/1MFvISGFKxM?feature=share).

## Features

- Request Inspection: Capture and log incoming HTTP requests, including headers, query parameters, and body content.
- Response Inspection: Log outgoing HTTP responses, allowing for detailed analysis of server behavior.
- Custom Error Handling: Supports custom error responses, such as returning a 502 Bad Gateway status with a descriptive error message when an error occurs.
- Lightweight and Fast: Built with Rust, Echo Proxy is highly efficient and performs well under various workloads.
- Easy Integration: Simple to set up and integrate into existing development and testing workflows.

## Usage

- To use Echo Proxy, follow these steps:Clone the Repository:

```
git clone https://github.com/lsk569937453/echo-proxy.git
cd echo-proxy
```

- Build the Project:

```
cargo build --release
```

## Run the Proxy

To run Echo Proxy, use the following command:

```
.\echo-proxy.exe -P 4848 -T http://127.0.0.1:8123
```

- -P 4848: Specifies the HTTP port on which the proxy will listen. In this example, the proxy listens on port 4848.
- -T http://127.0.0.1:8123: Specifies the target URL to which the proxy will forward the requests. In this example, the target URL is http://127.0.0.1:8123.

## Contributing

Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request. For major changes, please open an issue first to discuss the proposed changes.

## License

Echo Proxy is licensed under the MIT License. See the LICENSE file for more details.

## Support

For support, questions, or feature requests, please open an issue on the GitHub repository.
This README provides a comprehensive overview of Echo Proxy, its features, and how to use it effectively. It is written in a professional tone and is designed to be clear and helpful for developers.
