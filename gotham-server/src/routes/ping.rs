use rocket::http::Status;

#[get("/ping")]
pub fn ping() -> Status {
    // TODO: Add logic for health check
    Status::Ok
}
