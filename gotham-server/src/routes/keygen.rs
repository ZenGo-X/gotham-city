#[get("/world")]
pub fn world() -> &'static str {
    "Hello, world!"
}