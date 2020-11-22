use rocket::response::content;
use rocket_include_static_resources::{
    static_resources_initialize, static_response, StaticResponse,
};
use serde::{Deserialize, Serialize};

use crate::IP_MAP;

pub fn rocket() {
    println!("Running Webserver");
    rocket::ignite()
        .attach(StaticResponse::fairing(|resources| {
            static_resources_initialize!(resources, "icon", "data/icon.png",);
        }))
        .mount("/", routes![index, icon, json, license, js])
        .launch();
}

#[get("/")]
fn index() -> content::Html<String> {
    content::Html(include_str!("../data/index.html").to_string())
}

#[get("/map.js")]
fn js() -> content::JavaScript<String> {
    content::JavaScript(include_str!("../data/map.js").to_string())
}

#[get("/license")]
fn license() -> content::Html<String> {
    content::Html(include_str!("../data/license.html").to_string())
}

#[derive(Serialize, Deserialize)]
struct IPAddress {
    ip: String,
    latitude: String,
    longitude: String,
}

#[get("/map.json")]
fn json() -> content::Json<String> {
    let mut json: String = String::new();

    json.push_str("[\n");

    for a in &*IP_MAP.read().unwrap() {
        let address = IPAddress {
            ip: a[0].to_owned(),
            latitude: a[1].to_owned(),
            longitude: a[2].to_owned(),
        };

        let serialized = match serde_json::to_string(&address) {
            Ok(data) => data,
            Err(error) => {
                let error_string = format!("Error serializing JSON: {}", error);
                eprintln!("{}", error_string);
                error_string
            }
        };

        json.push_str(&format!("{},\n", serialized));
    }

    json = (&json[0..json.len() - 2]).to_string();
    json.push_str("\n]\n");

    content::Json(json)
}

#[get("/icon.png")]
fn icon() -> StaticResponse {
    static_response!("icon")
}
