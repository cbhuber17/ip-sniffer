use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::{env, process};

// Usage:
// ip-sniffer.exe -h
// ip-sniffer.exe -j 1000 192.168.1.1
// ip-sniffer.exe 192.168.1.1

struct Arguments {
    ipaddr: IpAddr,
    threads: u16,
}

impl Arguments {
    /// Creates a new `Arguments` instance from the command-line arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - A slice of strings representing the command-line arguments.
    ///
    /// # Returns
    ///
    /// * `Ok(Arguments)` if the arguments are valid.
    /// * `Err(&'static str)` if there is an error with the provided arguments.
    ///
    /// # Errors
    ///
    /// * "not enough arguments" if fewer than 2 arguments are provided.
    /// * "too many arguments" if more than 4 arguments are provided.
    /// * "help" if the help flag (`-h` or `-help`) is provided.
    /// * "too many arguments" if the help flag is provided with additional arguments.
    /// * "not a valid IPADDR; must be IPv4 or IPv6" if the IP address is invalid.
    /// * "failed to parse thread number" if the thread number is invalid.
    /// * "invalid syntax" if the arguments do not match the expected patterns.
    ///
    /// # Usage
    ///
    /// The following command-line argument patterns are recognized:
    ///
    /// * `<IPADDR>` - Specify the IP address to sniff (default number of threads is 4).
    /// * `-j <THREADS> <IPADDR>` - Specify the number of threads and the IP address to sniff.
    /// * `-h` or `-help` - Show the help message.
    // Static to send errors back to main and have main handle those errors
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 4 {
            return Err("too many arguments");
        }

        let f = args[1].clone();

        if let Ok(ipaddr) = IpAddr::from_str(&f) {
            return Ok(Arguments { ipaddr, threads: 4 });
        } else {
            let flag = args[1].clone();

            if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                println!("Usage:\n-j to select how many threads you want\n-h or -help to show this help message");
                return Err("help");
            } else if flag.contains("-h") || flag.contains("-help") {
                return Err("too many arguments");
            } else if flag.contains("-j") {
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    Ok(s) => s,
                    Err(_) => return Err("not a valid IPADDR; must be IPv4 or IPv6"),
                };

                let threads = match args[2].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => return Err("failed to parse thread number"),
                };

                return Ok(Arguments { threads, ipaddr });
            } else {
                return Err("invalid syntax");
            }
        }
    }
}

/// Scans for open ports on the specified IP address.
///
/// # Arguments
///
/// * `tx` - A `Sender<u16>` to send open port numbers to.
/// * `start_port` - The starting port number for the scan.
/// * `addr` - The IP address to scan.
/// * `num_threads` - The number of threads to use for the scan.
///
/// # Description
///
/// This function attempts to connect to each port starting from `start_port`
/// and incrementing by `num_threads` until the maximum value for a `u16` is reached.
/// If a connection is successful, it prints a dot (`.`) to the standard output,
/// flushes the output buffer, and sends the port number to the provided `Sender`.
/// The function runs in an infinite loop until the port number exceeds the maximum
/// value for a `u16`.
///
/// # Panics
///
/// This function will panic if it fails to flush the standard output buffer or send
/// the port number through the `Sender`.
fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    let mut port: u16 = start_port + 1;

    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }

        if u16::max_value() <= num_threads {
            break;
        }
        port += num_threads;
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem parsing arguments: {}", program, err);
            process::exit(0);
        }
    });

    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;
    let (tx, rx) = channel();

    for i in 0..num_threads {
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, addr, num_threads);
        });
    }

    let mut out = vec![];
    drop(tx);

    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();

    for v in out {
        println!("{} is open", v);
    }
}
