#![feature(plugin, custom_derive, macro_vis_matcher)]
#![plugin(rocket_codegen)]

extern crate base64;
extern crate bcrypt;
extern crate chrono;
extern crate config;
#[macro_use] extern crate lazy_static;
extern crate uuid;
#[macro_use] extern crate diesel;
#[macro_use] extern crate diesel_codegen;
extern crate r2d2;
extern crate r2d2_diesel;
extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;
#[macro_use] extern crate derive_builder;
extern crate rocket;
#[macro_use] extern crate log;

mod models;
mod persistence;
mod web;
mod utils;

lazy_static! {
  static ref SETTINGS: models::configuration::AppSettings = {
    use config::{Config, File as ConfigFile};
    let mut config_data = Config::new();
    config_data.merge(ConfigFile::with_name("config.toml")).unwrap();
    config_data.try_into().expect("Error initializing application settings from the config.toml file; crashing!")
  };
}

use diesel::pg::PgConnection;
use r2d2::Pool;
use r2d2_diesel::ConnectionManager;
lazy_static! {
  pub static ref DB_POOL: Pool<ConnectionManager<PgConnection>> = {
    let db_url = format!("postgres://{}:{}@{}:{}/{}", &SETTINGS.db.user, &SETTINGS.db.pass, &SETTINGS.db.host, SETTINGS.db.port, &SETTINGS.db.db_name);
    println!("db url: {}", &db_url);
    let manager = ConnectionManager::<PgConnection>::new(db_url);

    Pool::builder()
        .max_size(SETTINGS.db.pool_size)
        .build(manager)
        .expect("Failed to initialize the DB connection pool")
  };
}

fn main() {
  rocket::ignite()
    .mount("/", routes![
      web::routes::token,
      web::routes::introspect])
    .launch();
}
