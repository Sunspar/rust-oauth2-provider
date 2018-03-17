use diesel::pg::PgConnection;
use r2d2::Pool;
use r2d2_diesel::ConnectionManager;
use SETTINGS;

table! {
    clients (id) {
        id -> Integer,
        identifier -> VarChar,
        secret -> VarChar,
        response_type -> VarChar,
    }
}

table! {
    grant_types (id) {
        id -> Integer,
        name -> VarChar,
    }
}

table! { 
    client_redirect_uris (id) {
        id -> Integer,
        client_id -> Integer,
        redirect_uri -> VarChar,
    }
}

table! { 
    access_tokens (id) {
        id -> Integer,
        token -> Uuid,
        client_id -> Integer,
        grant_id -> Integer,
        scope -> VarChar,
        issued_at -> Timestamp,
        expires_at -> Timestamp,
    }
}

table! {
    refresh_tokens (id) {
        id -> Integer,
        token -> Uuid,
        client_id -> Integer,
        scope -> VarChar,
        issued_at -> Timestamp,
        expires_at -> Nullable<Timestamp>,
    }
}

table!{
    auth_codes (id) {
        id -> Integer,
        client_id -> Integer,
        name -> VarChar,
        scope -> VarChar,
        expires_at -> Timestamp,
        redirect_uri -> VarChar,
        user_id -> Nullable<Integer>,
    }
}