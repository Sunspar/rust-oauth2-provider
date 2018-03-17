#[derive(Builder, Clone, Debug, Deserialize, FromForm)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}
