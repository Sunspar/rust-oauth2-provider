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
extern crate serde_json;
#[macro_use] extern crate derive_builder;

// Iron dependencies
extern crate iron;
extern crate router;
extern crate urlencoded;

// Logging
#[macro_use] extern crate log;
extern crate log4rs;

// Custom headers use the hyper crate directly
#[macro_use] extern crate hyper;

use iron::prelude::*;
use std::env;
use router::Router;

mod models;
mod persistence;
mod web;
mod utils;

fn main() {
  dotenv::dotenv().ok();

	// Initialize logger
	log4rs::init_file("log4rs.yml", Default::default()).unwrap();

	// Set up the routes
	trace!("setting up the router");
	let mut router = Router::new();
	router.get("/oauth/authorize", web::routes::authorize, "authorize");
	router.post("/oauth/token", web::routes::token, "token");
	router.post("/oauth/introspect", web::routes::introspect, "introspect");

	// Set up midleware around requests
	trace!("Setting up the chain for middleware, etc");
	let mut chain = Chain::new(router);
	chain.link_after(web::middleware::AttachGeneralOAuth2Headers);
	info!("Booting up Iron...");
	Iron::new(chain).http(env::var("SERVER_URL_WITH_PORT").unwrap()).unwrap();
}
