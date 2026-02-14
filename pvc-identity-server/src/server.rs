// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::Engine;
use base64::engine::general_purpose;
use base64::prelude::BASE64_STANDARD;
use blind_rsa::signer::RsaBlindSigner;
use blind_rsa::{RsaBlindConfig, blinder::PublicKeyParts};
use rocket::State;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::serde::json::Json;
use serde_json::json;
use types::{
    ApiCode, ApiResult,
    keys::PublicKeyFields,
    keys::{BlindMessageRequest, BlindMessageResponse},
};

#[allow(dead_code)]
pub struct AuthToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthToken {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = req.headers().get_one("Authorization").unwrap_or("Bearer ");
        if !auth_header.starts_with("Bearer ") {
            return Outcome::Error((Status::BadRequest, ()));
        }
        let token = auth_header.trim_start_matches("Bearer ").trim().to_string();
        let validator = oauth::get_oauth_validator();
        match validator.validate(&token).await {
            Ok(_) => Outcome::Success(AuthToken(token)),
            Err(_) => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

/// Application state
pub struct AppState {
    pub signer: RsaBlindSigner,
}

/// Root endpoint
#[get("/")]
pub fn root() -> Json<serde_json::Value> {
    Json(json!({
        "status": "success",
        "message": "Identity server with blind RSA signature support",
        "endpoints": {
            "/pubkey": "Get the RSA public key in JSON format",
            "/sign": "Post a base64-encoded blinded message to get a blind signature"
        }
    }))
}

/// Public key endpoint
#[get("/pubkey")]
pub fn pubkey(state: &State<AppState>) -> ApiResult<PublicKeyFields> {
    let pk = state.signer.pubkey();

    let pubkey_comp = PublicKeyFields {
        n: BASE64_STANDARD.encode(pk.n().to_bytes_le()),
        e: BASE64_STANDARD.encode(pk.e().to_bytes_le()),
    };

    Ok(pubkey_comp).into()
}

/// Sign endpoint
#[post("/sign", format = "json", data = "<req>")]
pub fn sign(
    state: &State<AppState>,
    _token: AuthToken,
    req: Json<BlindMessageRequest>,
) -> ApiResult<BlindMessageResponse> {
    let logic = || -> Result<BlindMessageResponse, ApiCode> {
        let signature = state
            .signer
            .blind_sign(&req.blinded_message)
            .map_err(|_| ApiCode::BlindSignFailed)?;

        let sig_b64 = general_purpose::STANDARD.encode(&signature);

        Ok(BlindMessageResponse { signature: sig_b64 })
    };

    logic().into()
}

#[get("/health")]
fn health() -> &'static str {
    "ok"
}

/// Build Rocket instance
pub fn rocket_app() -> rocket::Rocket<rocket::Build> {
    let cfg = RsaBlindConfig::default();
    let signer = RsaBlindSigner::new(cfg);
    let state = AppState { signer };
    rocket::build()
        .manage(state)
        .mount("/", routes![root, pubkey, sign, health])
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::{
        BlindingResult, DefaultRng, Options, PublicKey,
        reexports::rsa::{BigUint, RsaPublicKey},
    };
    use rocket::local::blocking::Client;

    #[test]
    fn test_pubkey_endpoint() {
        let client = Client::tracked(rocket_app()).expect("valid rocket instance");
        let response = client.get("/pubkey").dispatch();
        assert_eq!(response.status().code, 200);

        let body = response.into_string().unwrap();
        assert!(body.contains("n"));
        assert!(body.contains("e"));
    }

    #[test]
    fn test_sign_endpoint() {
        let client = Client::tracked(rocket_app()).expect("valid rocket instance");

        let response = client.get("/pubkey").dispatch();
        let body = response.into_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let n_str = parsed["data"]["n"].as_str().unwrap();
        let e_str = parsed["data"]["e"].as_str().unwrap();

        let n = BigUint::from_bytes_le(&BASE64_STANDARD.decode(n_str).unwrap());
        let e = BigUint::from_bytes_le(&BASE64_STANDARD.decode(e_str).unwrap());
        let rsa_pk = RsaPublicKey::new(n, e).expect("invalid key components");
        let pk = PublicKey::new(rsa_pk);

        let options = Options::default();
        let rng = &mut DefaultRng::default();
        let message: &'static [u8; 12] = b"test message";
        let blind_result: BlindingResult = pk
            .blind(rng, message, true, &options)
            .expect("blind failed");
        // let blinded_b64 = base64_encode(&blind_result.blind_msg.0);

        let req_body = BlindMessageRequest {
            blinded_message: blind_result.blind_msg.0,
        };
        let response = client
            .post("/sign")
            .header(rocket::http::ContentType::JSON)
            .body(serde_json::to_string(&req_body).unwrap())
            .dispatch();

        assert_eq!(response.status().code, 200);
        let body = response.into_string().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["code"], 0);
        assert!(parsed["data"]["signature"].as_str().unwrap().len() > 0);
    }
}
