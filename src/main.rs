extern crate base64;
extern crate bcrypt;
extern crate chrono;
extern crate config;
#[macro_use] extern crate derive_builder;
#[macro_use] extern crate diesel;
#[macro_use] extern crate log;
extern crate log4rs;
extern crate once_cell;
extern crate r2d2;
extern crate r2d2_diesel;
#[macro_use] extern crate rocket;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

mod models;
mod persistence;
mod utils;
mod handlers;

use diesel::pg::PgConnection;
use once_cell::sync::Lazy;
use r2d2::Pool;
use r2d2_diesel::ConnectionManager;

static SETTINGS: Lazy<models::configuration::AppSettings> = Lazy::new(|| {
    use config::Config;
    
    let config_data = Config::builder()
        .add_source(config::File::with_name("config.toml"))
        .build()
        .expect("Error initializing application settings from the config.toml file; crashing!");
    
    config_data.try_deserialize()
        .expect("Failed to interpret configuration file as application settings data.")
});

static DB_POOL: Lazy<Pool<ConnectionManager<PgConnection>>> = Lazy::new(|| {
    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        &SETTINGS.db.user,
        &SETTINGS.db.pass,
        &SETTINGS.db.host,
        SETTINGS.db.port,
        &SETTINGS.db.db_name
    );
    debug!("db url: {}", &db_url);
    let manager = ConnectionManager::<PgConnection>::new(db_url);

    Pool::builder()
        .max_size(SETTINGS.db.pool_size)
        .build(manager)
        .expect("Failed to initialize the DB connection pool")
});

#[launch]
fn rocket() -> _ {
    log4rs::init_file(".log4rs.yml", Default::default()).unwrap();

    rocket::build()
        .mount("/", routes![
            crate::handlers::token::post,
            crate::handlers::introspect::post
        ])
}