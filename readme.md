# Scan Me - v0.1

Scan Me is a simple Rust-based network scanner that allows users to input IP addresses or ranges of IP addresses to scan for open ports. The program uses system pings to check if the IP addresses are reachable and then scans the specified ports to determine their state (open, closed, or filtered).

## Notes 
Initial version, the scanner is limited to certain ports for the moment:
    FTP: 20, 21
    SSH: 22
    Telnet: 23
    SMTP: 25
    DNS: 53
    NetBIOS over TCP: 137, 139
    SMB: 445
    HTTP/HTTPS: 80, 443, 8080, 8443
    Database services: 1433, 1434, 3306
    Remote desktop: 3389
    
Many improvements are still to come to the code... and other more features to come later.

## Features

- **User Input for IP Addresses**: The program prompts the user to enter an IP address, a range of IP addresses, or a list of IP addresses to scan.
- **IP Address Parsing**: The program parses the user input to handle single IP addresses, ranges of IP addresses, and lists of IP addresses.
- **System Ping**: The program uses system pings to check if the IP addresses are reachable.
- **Port Scanning**: The program scans a predefined list of target ports on the reachable IP addresses to determine their state (open, closed, or filtered).
- **Results Display**: The program displays the scan results in a table format, showing the IP address, port, service name, state, and any errors.

## Usage

1. **Run the Program**: Execute the program using `cargo run`.
2. **Enter IP Addresses**: When prompted, enter an IP address, a range of IP addresses (e.g., `192.168.1.1-192.168.1.254`), or a list of IP addresses (e.g., `192.168.1.1,192.168.1.2`).
3. **View Results**: The program will display the scan results in a table format.

## How to Run

1. Ensure you have Rust installed. If not, you can install it from [rust-lang.org](https://www.rust-lang.org/).
2. Clone this repository.
3. Navigate to the project directory.
4. Run the application using Cargo:

```sh
cargo run
```

## Example

```sh
$ cargo run
Scan Me - v0.1 - MSC 2025
----------------------------------------------------------------------------------

---------------------------------------------------------------------------------------------------------------------------------------
Enter the IP address or range of IP addresses to scan (e.g., 192.168.1.1-192.168.1.254 or 192.168.1.1,192.168.1.2) or 'q' to quit:
---------------------------------------------------------------------------------------------------------------------------------------

192.168.1.1-192.168.1.254

IP Address       Port    Service             State       Error
192.168.1.1      22      SSH                 Open        
192.168.1.1      80      HTTP/HTTPS          Closed      
192.168.1.2      22      SSH                 Filtered    
192.168.1.2      80      HTTP/HTTPS          Open        
...
```

## Dependencies
Add the following dependencies to your `Cargo.toml` file:

```toml
[dependencies]
pnet = "0.32.0"
ipnet = "2.9.0"
comfy-table = "6.1"
tokio = { version = "1", features = ["full"] }
```

## Code Overview

### Main Function

The `main` function initializes the program, clears the screen, and enters a loop to continuously prompt the user for IP addresses to scan. It handles user input, parses the IP addresses, and spawns asynchronous tasks to ping and scan the IP addresses.

### Functions

- **`get_ip_input`**: Prompts the user to enter IP addresses and returns the input as a string.
- **`parse_ip_input`**: Parses the user input to handle single IP addresses, ranges of IP addresses, and lists of IP addresses. Returns a `Result` containing a vector of `IpAddr` or an error message.
```rust
/// Parse user input for IP addresses
fn parse_ip_input(input: &str) -> Result<Vec<IpAddr>, String> {
    if input.contains('-') {
        // Range of IP addresses
        let parts: Vec<&str> = input.split('-').collect();
        if parts.len() == 2 {
            let start_ip = IpAddr::from_str(parts[0]).map_err(|_| "Invalid start IP address")?;
            let end_ip = IpAddr::from_str(parts[1]).map_err(|_| "Invalid end IP address")?;
            if let (IpAddr::V4(start), IpAddr::V4(end)) = (start_ip, end_ip) {
                let start_u32 = u32::from(start);
                let end_u32 = u32::from(end);
                if start_u32 > end_u32 {
                    return Err("Invalid IP address range".to_string());
                }
                return Ok((start_u32..=end_u32)
                    .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
                    .collect());
            } else {
                return Err("IPv6 addresses are not supported for ranges".to_string());
            }
        } else {
            return Err("Invalid IP address range format".to_string());
        }
    } else if input.contains(',') {
        // List of IP addresses
        return input.split(',')
            .map(|ip| IpAddr::from_str(ip.trim()).map_err(|_| "Invalid IP address".to_string()))
            .collect();
    }
    // Single IP address
    IpAddr::from_str(input).map(|ip| vec![ip]).map_err(|_| "Invalid IP address".to_string())
}
```

- **`ping_ip`**: Uses system pings (for the moment) to check if an IP address is reachable. Returns a boolean indicating the reachability of the IP address.
- **`scan_ports`**: Scans the specified ports on a given IP address to determine their state (open, closed, or filtered). Updates the scan results.
```rust
/// Scan ports on the given IP address
async fn scan_ports(ip: &IpAddr, results: Arc<Mutex<Vec<ScanResult>>>) {
    for port in TARGET_PORTS {
        let mut result = ScanResult {
            ip: *ip,
            port,
            state: "Filtered".to_string(),
            error: "".to_string(),
        };

        let results = Arc::clone(&results);
        let scan_future = async move {
            let socket = SocketAddr::new(*ip, port);
            match timeout(Duration::from_millis(500), TcpStream::connect(socket)).await {
                Ok(Ok(_)) => {
                    result.state = "Open".to_string();
                }
                Ok(Err(_)) => {
                    result.state = "Closed".to_string();
                }
                Err(_) => {
                    // If connection failed: try RST
                    let mut rst_result = ScanResult {
                        ip: *ip,
                        port,
                        state: "Filtered".to_string(),
                        error: "".to_string(),
                    };
                    if scan_tcp_rst(&ip, port, &mut rst_result).await {
                        result.state = rst_result.state;
                    }
                }
            }

            let mut results_guard = results.lock().unwrap();
            results_guard.push(result);
        };

        scan_future.await;
    }
}
```

- **`scan_tcp_rst`**: Performs a TCP RST scan on a given IP address and port to determine if the port is filtered.
```rust
/// Scan TCP RST
async fn scan_tcp_rst(ip: &IpAddr, port: u16, result: &mut ScanResult) -> bool {
    let socket = SocketAddr::new(*ip, port);
    match timeout(Duration::from_millis(500), TcpStream::connect(socket)).await {
        Ok(Ok(_)) => {
            result.state = "Open".to_string();
            true
        }
        Ok(Err(ref e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            result.state = "Closed".to_string();
            true
        }
        Ok(Err(_)) | Err(_) => {
            result.state = "Filtered".to_string();
            false
        }
    }
}
```

- **`get_port_name`**: Returns the service name for a given port.
- **`display_results`**: Displays the scan results in a table format.

### Data Structures

- **`ScanResult`**: A struct to store the scan results, including the IP address, port, state, and any errors.

### Constants

- **`TARGET_PORTS`**: A predefined list of target ports to scan.
```rust
// Define target ports
const TARGET_PORTS: [u16; 15] = [20, 21, 22, 23, 25, 53, 137, 139, 445, 80, 443, 8080, 8443, 1433, 3306];
```

## Conclusion

This project is a simple exercise to demonstrate various Rust programming concepts. It is not intended to be a fully functional application but rather an educational tool to help you learn Rust. Feel free to explore the code, modify it, and experiment with different features to deepen your understanding of Rust.

Have fun, Rust in peace!

MSC
