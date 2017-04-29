use diesel::pg::PgConnection;
use r2d2::{Config, Pool};
use r2d2_diesel::ConnectionManager;
use std::env;

infer_schema!("dotenv:DATABASE_URL");

lazy_static! {
    pub static ref DB_POOL: Pool<ConnectionManager<PgConnection>> = init_db_pool();
}

fn init_db_pool() -> Pool<ConnectionManager<PgConnection>> {
  let config = Config::builder()
    .pool_size(10)
    .build();
  let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
  let manager = ConnectionManager::<PgConnection>::new(db_url);
  Pool::new(config, manager).expect("Failed to create pool.")
}
