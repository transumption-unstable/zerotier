use failure::Fail;

#[derive(Debug, Fail)]
pub enum InternalError {
    #[fail(display = "incorrect input length")]
    BytesLengthError,
    #[fail(display = "invalid hashcash")]
    InvalidHashcash,
    #[fail(display = "malformed identity")]
    MalformedIdentity,
    #[fail(display = "reserved address")]
    ReservedAddress,
}
