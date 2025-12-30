// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rocket::{
    Request, Response,
    fairing::{Fairing, Info, Kind},
};

pub struct HeaderLogger;
#[rocket::async_trait]
impl Fairing for HeaderLogger {
    fn info(&self) -> Info {
        Info {
            name: "Request/Response Header Logger",
            kind: Kind::Response,
        }
    }
    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        if req.uri().path() == "/health" {
            return;
        }
        info!("--- [{} {}] ---", req.method(), req.uri());

        let headers = req.headers();
        for header in headers.iter() {
            // header.name() & header.value()
            info!("{}: {}", header.name().as_str(), header.value());
        }
        info!("--- Outcome: {} ---", res.status());
    }
}
