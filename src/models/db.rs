use chrono::NaiveDateTime;
use std::fmt;
use uuid::Uuid;

use crate::persistence::*;

#[derive(Builder, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name = "clients"]
pub struct Client {
    pub id: i32,
    pub identifier: String,
    pub secret: String,
    pub response_type: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Client {{ id: {}, identifier: {}, secret: [REDACTED], response_type: {} }}",
            self.id, self.identifier, self.response_type
        )
    }
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name = "grant_types"]
pub struct GrantType {
    pub id: i32,
    pub name: String,
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name = "access_tokens"]
pub struct AccessToken {
    pub id: i32,
    pub token: Uuid,
    pub client_id: i32,
    pub grant_id: i32,
    pub scope: String,
    pub issued_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name = "access_tokens"]
pub struct NewAccessToken {
    pub client_id: i32,
    pub grant_id: i32,
    pub scope: String,
    pub issued_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

#[derive(Builder, Debug, Serialize, Deserialize, Identifiable, Queryable, Associations)]
#[builder(setter(into))]
#[table_name = "refresh_tokens"]
pub struct RefreshToken {
    pub id: i32,
    pub token: Uuid,
    pub client_id: i32,
    pub scope: String,
    pub issued_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
}

#[derive(Builder, Debug, Serialize, Deserialize, Insertable)]
#[builder(setter(into))]
#[table_name = "refresh_tokens"]
pub struct NewRefreshToken {
    pub client_id: i32,
    pub scope: String,
    pub issued_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
}
