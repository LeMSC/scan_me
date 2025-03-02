use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::time::timeout;
use comfy_table::{Table, Cell, Attribute, Color};
use tokio::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::io;
use std::process::Command;

#[tokio::main]
async fn main() {
    // Clear the screen
    print!("\x1B[2J\x1B[1;1H");
    println!("Scan Me - v0.1 - MSC 2025");
    println!("----------------------------------------------------------------------------------");
    println!();

    loop {
        // User input for IP addresses
        let ip_input = get_ip_input();
        if ip_input.to_lowercase() == "q" {
            break;
        }
        let ip_addresses = match parse_ip_input(&ip_input) {
            Ok(addresses) => addresses,
            Err(e) => {
                println!("Error: {}", e);
                continue;
            }
        };

        // Scan IP addresses and ports
        let results: Arc<Mutex<Vec<ScanResult>>> = Arc::new(Mutex::new(Vec::new()));

        // Scanning in separate tasks
        let mut handles = vec![];
        for ip in ip_addresses {
            let cloned_results = Arc::clone(&results);
            let handle = tokio::spawn(async move {
                if ping_ip(&ip).await {
                    scan_ports(&ip, cloned_results).await;
                } else {
                    let mut results_guard = cloned_results.lock().unwrap();
                    results_guard.push(ScanResult {
                        ip,
                        port: 0,
                        state: "Unreachable".to_string(),
                        error: "".to_string(),
                    });
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // Display results in a table
        display_results(&mut results.lock().unwrap());
    }
}

/// Get user input for IP addresses
fn get_ip_input() -> String {
    println!();
    println!("---------------------------------------------------------------------------------------------------------------------------------------");
    println!("Enter the IP address or range of IP addresses to scan (e.g., 192.168.1.1-192.168.1.254 or 192.168.1.1,192.168.1.2) or 'q' to quit:");
    println!("---------------------------------------------------------------------------------------------------------------------------------------");
    println!();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}

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

/// Check if the IP is reachable by sending a system ping
/// Not very elegant, consider replacing with a crate like tokio-ping
async fn ping_ip(ip: &IpAddr) -> bool {
    let output = if cfg!(target_os = "windows") {
        Command::new("ping")
            .arg("-n")
            .arg("1")
            .arg(ip.to_string())
            .output()
            .expect("Failed to execute ping command")
    } else {
        Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg(ip.to_string())
            .output()
            .expect("Failed to execute ping command")
    };

    output.status.success()
}

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

/// Get the service name for a given port
fn get_port_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        137 | 139 => "NetBIOS over TCP",
        445 => "SMB",
        80 | 443 | 8080 | 8443 => "HTTP/HTTPS",
        1433 | 1434 | 3306 => "Database services",
        3389 => "Remote Desktop",
        _ => "Unknown",
    }
}

/// Display results in a table
fn display_results(results: &mut Vec<ScanResult>) {
    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("IP Address").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Port").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Service").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("State").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Error").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    results.sort_by_key(|r| (r.ip, r.port));

    for result in results {
        let mut state_cell = Cell::new(&result.state);
        match result.state.as_str() {
            "Open" => state_cell = state_cell.fg(Color::Green),
            "Closed" => state_cell = state_cell.fg(Color::Red),
            "Filtered" => state_cell = state_cell.fg(Color::Yellow),
            "Unreachable" => state_cell = state_cell.fg(Color::Magenta),
            _ => {}
        }

        table.add_row(vec![
            Cell::new(result.ip.to_string()),
            Cell::new(result.port.to_string()),
            Cell::new(get_port_name(result.port)),
            state_cell,
            Cell::new(&result.error),
        ]);
    }

    println!("{}", table);
}

// Define target ports
const TARGET_PORTS: [u16; 15] = [20, 21, 22, 23, 25, 53, 137, 139, 445, 80, 443, 8080, 8443, 1433, 3306];

// Structure to store scan results
#[derive(Debug, Clone)]
struct ScanResult {
    ip: IpAddr,
    port: u16,
    state: String,
    error: String,
}
