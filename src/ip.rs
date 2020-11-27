use casual_logger::Log;
use clap::ArgMatches;
use etherparse::{InternetSlice, SlicedPacket};
use ipgeolocate::Locator;
use pcap::Device;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::IP_MAP;

pub fn ipextract(app: ArgMatches<'static>) {
    println!("Running IP Detection");

    if app.is_present("output") {};

    let mut threads = vec![];
    let ip_index = Arc::new(Mutex::new(HashSet::new()));
    let latitude_index = Arc::new(Mutex::new(HashSet::new()));
    let longitude_index = Arc::new(Mutex::new(HashSet::new()));

    // Listen on all interfaces
    Device::list().unwrap().into_iter().for_each(|interface| {
        let ip_index = ip_index.clone();
        let latitude_index = latitude_index.clone();
        let longitude_index = longitude_index.clone();
        let app = app.clone();

        threads.push(std::thread::spawn(move || {
            // Some interfaces are not meant for listening onto
            // So we ignore them
            let mut interface = match interface.open() {
                Ok(int) => int,
                Err(_) => return,
            };

            // Loop through each packet in the capture interface as an iterator until it returns an error.
            while let Ok(packet) = interface.next() {
                match SlicedPacket::from_ethernet(packet.data) {
                    Err(error) => {
                        Log::error(&error.to_string());
                    }
                    Ok(value) => match value.ip {
                        Some(InternetSlice::Ipv4(header)) => {
                            let mut ip_index = ip_index.lock().unwrap();
                            let mut latitude_index = latitude_index.lock().unwrap();
                            let mut longitude_index = longitude_index.lock().unwrap();

                            let current_ip = header.source_addr();
                            if !ip_index.contains(&current_ip.to_string())
                                && !current_ip.is_private()
                            {
                                ip_index.insert(current_ip.to_string());

                                if app.value_of("service") == Some("ipwhois") {
                                    // Run locator with the IP address, which returns Latitude and Longitude.
                                    match Locator::ipwhois(current_ip.to_string().as_str()) {
                                        Ok(ip) => {
                                            if !latitude_index.contains(&ip.longitude.to_string()) {
                                                if !longitude_index
                                                    .contains(&ip.longitude.to_string())
                                                {
                                                    IP_MAP.write().unwrap().push([
                                                        ip.ip.clone(),
                                                        ip.latitude.to_string().clone(),
                                                        ip.longitude.to_string().clone(),
                                                    ]);

                                                    println!("{} ({})", ip.ip, ip.city);
                                                    longitude_index
                                                        .insert(ip.longitude.to_string());
                                                }
                                                latitude_index.insert(ip.latitude.to_string());
                                            }
                                        }
                                        // If there was an error, send it to the logs.
                                        Err(error) => {
                                            eprintln!(
                                                "ipwhois error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            );
                                            Log::error(&format!(
                                                "ipwhois error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            ));
                                        }
                                    }
                                } else if app.value_of("service") == Some("freegeoip") {
                                    // Run locator with the IP address, which returns Latitude and Longitude.
                                    match Locator::freegeoip(current_ip.to_string().as_str()) {
                                        Ok(ip) => {
                                            if !latitude_index.contains(&ip.longitude.to_string()) {
                                                if !longitude_index
                                                    .contains(&ip.longitude.to_string())
                                                {
                                                    IP_MAP.write().unwrap().push([
                                                        ip.ip.clone(),
                                                        ip.latitude.to_string().clone(),
                                                        ip.longitude.to_string().clone(),
                                                    ]);

                                                    println!("{} ({})", ip.ip, ip.city);
                                                    longitude_index
                                                        .insert(ip.longitude.to_string());
                                                }
                                                latitude_index.insert(ip.latitude.to_string());
                                            }
                                        }
                                        // If there was an error, send it to the logs.
                                        Err(error) => {
                                            eprintln!(
                                                "freegeoip error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            );
                                            Log::error(&format!(
                                                "freegeoip error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            ));
                                        }
                                    }
                                } else if app.value_of("service") == Some("ipapi") {
                                    // Run locator with the IP address, which returns Latitude and Longitude.
                                    match Locator::ipapi(current_ip.to_string().as_str()) {
                                        Ok(ip) => {
                                            if !latitude_index.contains(&ip.longitude.to_string()) {
                                                if !longitude_index
                                                    .contains(&ip.longitude.to_string())
                                                {
                                                    IP_MAP.write().unwrap().push([
                                                        ip.ip.clone(),
                                                        ip.latitude.to_string().clone(),
                                                        ip.longitude.to_string().clone(),
                                                    ]);

                                                    println!("{} ({})", ip.ip, ip.city);
                                                    longitude_index
                                                        .insert(ip.longitude.to_string());
                                                }
                                                latitude_index.insert(ip.latitude.to_string());
                                            }
                                        }
                                        // If there was an error, send it to the logs.
                                        Err(error) => {
                                            eprintln!(
                                                "ipapi error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            );
                                            Log::error(&format!(
                                                "ipapi error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            ));
                                        }
                                    }
                                } else if app.value_of("service") == Some("ipapico") {
                                    // Run locator with the IP address, which returns Latitude and Longitude.
                                    match Locator::ipapico(current_ip.to_string().as_str()) {
                                        Ok(ip) => {
                                            if !latitude_index.contains(&ip.longitude.to_string()) {
                                                if !longitude_index
                                                    .contains(&ip.longitude.to_string())
                                                {
                                                    IP_MAP.write().unwrap().push([
                                                        ip.ip.clone(),
                                                        ip.latitude.to_string().clone(),
                                                        ip.longitude.to_string().clone(),
                                                    ]);

                                                    println!("{} ({})", ip.ip, ip.city);
                                                    longitude_index
                                                        .insert(ip.longitude.to_string());
                                                }
                                                latitude_index.insert(ip.latitude.to_string());
                                            }
                                        }
                                        // If there was an error, send it to the logs.
                                        Err(error) => {
                                            eprintln!(
                                                "ipapico error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            );
                                            Log::error(&format!(
                                                "ipapico error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            ));
                                        }
                                    }
                                } else {
                                    // Run locator with the IP address, which returns Latitude and Longitude.
                                    match Locator::ipapi(current_ip.to_string().as_str()) {
                                        Ok(ip) => {
                                            if !latitude_index.contains(&ip.longitude.to_string()) {
                                                if !longitude_index
                                                    .contains(&ip.longitude.to_string())
                                                {
                                                    IP_MAP.write().unwrap().push([
                                                        ip.ip.clone(),
                                                        ip.latitude.to_string().clone(),
                                                        ip.longitude.to_string().clone(),
                                                    ]);

                                                    println!("{} ({})", ip.ip, ip.city);
                                                    longitude_index
                                                        .insert(ip.longitude.to_string());
                                                }
                                                latitude_index.insert(ip.latitude.to_string());
                                            }
                                        }
                                        // If there was an error, send it to the logs.
                                        Err(error) => {
                                            eprintln!(
                                                "ipapi error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            );
                                            Log::error(&format!(
                                                "ipapi error: {} ({})",
                                                current_ip.to_string(),
                                                error
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        Some(_) | None => (),
                    },
                }
            }
        }));
    });

    threads.into_iter().for_each(|thread| {
        thread.join().unwrap();
    });
}
