#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

extern crate chrono;
#[macro_use] extern crate derive_builder;
#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_codegen;
extern crate dotenv;
#[macro_use] extern crate lazy_static;
extern crate rocket;
extern crate rocket_contrib;
extern crate r2d2;
extern crate r2d2_diesel;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;

mod models;
mod persistence;
mod routes;

fn main() {
  dotenv::dotenv().ok();

  rocket::ignite()
    .mount("/oauth", routes![
      routes::authorize, 
      routes::token_request,
      routes::token_introspection])
    .launch();
}
