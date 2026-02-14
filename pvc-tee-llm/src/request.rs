use crate::session::{Sessions, Sid};
use anyhow::Result;
use blind_rsa_signatures::reexports::{
    hmac_sha512::sha384::Hash,
    rsa::{Pss, PublicKey, RsaPublicKey},
};
use rocket::{
    Request, State,
    data::{self, Data, FromData},
    http::Status,
    outcome::Outcome,
    request::{self, FromRequest},
};

#[derive(Debug)]
#[allow(dead_code)]
pub enum RequestError {
    MissingIdentityToken,
    MissingIdentityMessage,
    MissingSessionId,
    InvalidSessionId,
    InvalidRequestData,
    InternalServerError,
}

/// A wrapper type that automatically decrypts using noise protocol.
/// This middleware performs both operations before the route handler receives the data.
/// Note: This requires the request to have valid X-Session-ID header and Sessions state.
#[derive(Debug)]
pub struct CleartextPayload(Vec<u8>);

impl CleartextPayload {
    #[allow(dead_code)]
    /// Consumes the wrapper and returns the decrypted bytes
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Returns a reference to the decrypted bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[async_trait]
impl<'r> FromData<'r> for CleartextPayload {
    type Error = RequestError;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        use rocket::data::ToByteUnit;
        let sid = match request.guard::<Sid>().await {
            Outcome::Success(sid) => sid,
            Outcome::Error(e) => {
                return data::Outcome::Error(e);
            }
            Outcome::Forward(_) => {
                return data::Outcome::Error((
                    Status::InternalServerError,
                    RequestError::InternalServerError,
                ));
            }
        };

        // Get the Sessions state from the request
        let sessions_outcome = request.guard::<&State<Sessions>>().await;
        let sessions: &State<Sessions> = match sessions_outcome {
            Outcome::Success(sessions) => sessions,
            Outcome::Error((status, _)) => {
                error!("Missing Sessions state in CleartextPayload middleware");
                return data::Outcome::Error((status, RequestError::InternalServerError));
            }
            Outcome::Forward(_) => {
                error!("Sessions state guard forwarded in CleartextPayload middleware");
                return data::Outcome::Error((
                    Status::InternalServerError,
                    RequestError::InternalServerError,
                ));
            }
        };

        // Read the raw bytes from the data stream with a reasonable limit
        let bytes = match data.open(50.megabytes()).into_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request data: {}", e);
                return data::Outcome::Error((
                    Status::BadRequest,
                    RequestError::InvalidRequestData,
                ));
            }
        };

        let session = match sessions.get(&sid).await {
            Ok(s) => s,
            Err(_) => {
                return data::Outcome::Error((Status::BadRequest, RequestError::InvalidSessionId));
            }
        };

        // Decrypt using noise protocol
        match session.lock().await.decrypt(bytes.as_slice()) {
            Ok(decrypted) => data::Outcome::Success(CleartextPayload(decrypted)),
            Err(status) => {
                error!("Failed to decrypt noise data with status: {}", status);
                data::Outcome::Error((Status::BadRequest, RequestError::InvalidRequestData))
            }
        }
    }
}

const IDENTITY_TOKEN_HEADER: &str = "X-Identity-Token";
const IDENTITY_MESSAGE_HEADER: &str = "X-Identity-Message";
#[allow(dead_code)]
pub struct IdentityToken {
    sig: Vec<u8>,
    msg: Vec<u8>,
}

impl IdentityToken {
    pub fn verify(&self, pk: &RsaPublicKey) -> Result<()> {
        let verifying_key = Pss::new::<Hash>();
        let mut hash = Hash::new();
        hash.update(&self.msg);
        let hashd = hash.finalize();
        pk.verify(verifying_key, &hashd, &self.sig)?;
        Ok(())
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for IdentityToken {
    type Error = RequestError;

    /// Extracts an IdentityToken from the HTTP request headers.
    /// This implementation allows IdentityToken to be used as a request guard in Rocket routes.
    ///
    /// # How it works:
    /// 1. Looks for the "X-Identity-Token" header in the incoming request
    /// 2. If found, logs the token and returns a successful Outcome containing the IdentityToken
    /// 3. If not found, returns an Error Outcome with Unauthorized status
    ///
    /// # Usage in routes:
    /// ```rust
    /// #[post("/endpoint")]
    /// async fn endpoint(token: IdentityToken) -> Result<...> {
    ///     // token is automatically extracted from headers
    /// }
    /// ```
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one(IDENTITY_TOKEN_HEADER);
        let msg = request.headers().get_one(IDENTITY_MESSAGE_HEADER);
        if token.is_none() {
            return Outcome::Error((Status::Unauthorized, Self::Error::MissingIdentityToken));
        }
        if msg.is_none() {
            return Outcome::Error((Status::Unauthorized, Self::Error::MissingIdentityMessage));
        }
        let sig = match hex::decode(token.unwrap()) {
            Ok(sig) => sig,
            Err(_) => {
                return Outcome::Error((Status::Unauthorized, Self::Error::MissingIdentityToken));
            }
        };
        let msg = match hex::decode(msg.unwrap()) {
            Ok(msg) => msg,
            Err(_) => {
                return Outcome::Error((Status::Unauthorized, Self::Error::MissingIdentityToken));
            }
        };
        Outcome::Success(IdentityToken { sig, msg })
    }
}
