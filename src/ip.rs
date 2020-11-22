use crate::IP_MAP;
use casual_logger::Log;
use ipgeolocate::Locator;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub fn ipextract() {
    println!("Running IP Detection");

    let mut t = vec![];
    let ip_index = Arc::new(Mutex::new(HashSet::new()));
    let latitude_index = Arc::new(Mutex::new(HashSet::new()));
    let longitude_index = Arc::new(Mutex::new(HashSet::new()));

    let i = sniff::sniffer::get_networks(None).unwrap();
    i.network_interfaces
        .into_iter()
        .zip(i.network_frames.into_iter())
        .for_each(|(ii, f)| {
            let ip_index = ip_index.clone();
            let latitude_index = latitude_index.clone();
            let longitude_index = longitude_index.clone();
            t.push(std::thread::spawn(move || {
                let mut ss = sniff::sniffer::Sniffer::new(ii, f, false);
                loop {
                    let p = match ss.next() {
                        Some(p) => p,
                        None => continue,
                    };
                    let current_ip = p.connection.remote_socket.ip;
                    let current_ip = match current_ip {
                        std::net::IpAddr::V4(ip) => ip,
                        std::net::IpAddr::V6(_) => continue,
                    };

                    let mut ip_index = ip_index.lock().unwrap();
                    let mut latitude_index = latitude_index.lock().unwrap();
                    let mut longitude_index = longitude_index.lock().unwrap();

                    if !ip_index.contains(&current_ip.to_string()) {
                        //&& !current_ip.is_private() {
                        ip_index.insert(current_ip.to_string());

                        // Run locator with the IP address, which returns Latitude and Longitude.

                        match Locator::get_ipv4(current_ip) {
                            Ok(ip) => {
                                if !latitude_index.contains(&ip.longitude) {
                                    if !longitude_index.contains(&ip.longitude) {
                                        IP_MAP.write().unwrap().push([
                                            ip.ip.clone(),
                                            ip.latitude.clone(),
                                            ip.longitude.clone(),
                                        ]);

                                        println!("{} ({})", ip.ip, ip.city);
                                        longitude_index.insert(ip.longitude);
                                    }
                                    latitude_index.insert(ip.latitude);
                                }
                            }
                            // If there was an error, send it to the logs.
                            Err(error) => {
                                eprintln!("location error: {} ({})", current_ip.to_string(), error);
                                Log::error(&format!(
                                    "Location error: {} ({})",
                                    current_ip.to_string(),
                                    error
                                ));
                            }
                        }
                    }
                }
            }));
        });

    t.into_iter().for_each(|t| {
        t.join().unwrap();
    });
    // Loop through each packet in the capture interface as an iterator until it returns an error.
}
