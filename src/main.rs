#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

extern crate base64;
extern crate bcrypt;
extern crate chrono;
extern crate dotenv;
#[macro_use] extern crate lazy_static;
extern crate uuid;

// Database
#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_codegen;
extern crate r2d2;
extern crate r2d2_diesel;

// Data Manipulation
extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate derive_builder;

// Web Framework - Rocket
extern crate rocket;

// Logging
#[macro_use] extern crate log;
extern crate log4rs;

mod models;
mod persistence;
mod web;
mod utils;

#[cfg(test)] mod test;

fn main() {
  dotenv::dotenv().ok();
  rocket::ignite()
    .mount("/", routes![
      web::routes::token,
      web::routes::introspect])
    .launch();
}
