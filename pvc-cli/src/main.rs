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

mod commands {
    pub mod attest;
    pub mod chat;
    pub mod login;
    pub mod session;
    pub mod upload;
}
mod config;
mod file_input;
mod output;
mod session;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use commands::{attest, chat, login, session as session_commands, upload};
use config::ProfileOverrides;
use output::OutputMode;

#[derive(Debug, Parser)]
#[command(name = "pvc-cli")]
#[command(about = "PVC command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Login(LoginArgs),
    Attest(AttestArgs),
    Chat(ChatArgs),
    Upload(UploadArgs),
    Session(SessionArgs),
}

#[derive(Debug, Args)]
struct LoginArgs {
    #[arg(long)]
    identity_server_url: Option<String>,
    #[arg(long)]
    gateway_url: Option<String>,
    #[arg(long)]
    relay_url: Option<String>,
    #[arg(long)]
    target_url: Option<String>,
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    token_env_var: Option<String>,
    #[arg(long, default_value_t = false)]
    token_stdin: bool,
    #[arg(long, default_value_t = false)]
    interactive: bool,
}

#[derive(Debug, Args)]
struct AttestArgs {
    #[arg(long)]
    identity_server_url: Option<String>,
    #[arg(long)]
    gateway_url: Option<String>,
    #[arg(long)]
    relay_url: Option<String>,
    #[arg(long)]
    target_url: Option<String>,
    #[arg(long)]
    nonce: Option<String>,
    #[arg(long, default_value = "human")]
    output: String,
}

#[derive(Debug, Args)]
struct ChatArgs {
    #[arg(long, help = "Send a single prompt; omit to start interactive chat")]
    prompt: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        help = "Read a single prompt from stdin instead of starting interactive chat"
    )]
    prompt_stdin: bool,
    #[arg(long)]
    model: Option<String>,
    #[arg(long, default_value = "human")]
    output: String,
}

#[derive(Debug, Args)]
struct UploadArgs {
    path: String,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionSubcommand,
    #[arg(long, default_value = "human")]
    output: String,
}

#[derive(Debug, Subcommand)]
enum SessionSubcommand {
    Show,
    Clear,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Login(args) => {
            login::run(login::LoginCommand {
                overrides: ProfileOverrides {
                    identity_server_url: args.identity_server_url,
                    gateway_url: args.gateway_url,
                    relay_url: args.relay_url,
                    target_url: args.target_url,
                },
                token: args.token,
                token_env_var: args.token_env_var,
                token_stdin: args.token_stdin,
                interactive: args.interactive,
            })
            .await
        }
        Commands::Attest(args) => {
            let output = OutputMode::parse(&args.output)?;
            attest::run(attest::AttestCommand {
                overrides: ProfileOverrides {
                    identity_server_url: args.identity_server_url,
                    gateway_url: args.gateway_url,
                    relay_url: args.relay_url,
                    target_url: args.target_url,
                },
                nonce: args.nonce,
                output,
            })
            .await
        }
        Commands::Chat(args) => {
            let output = OutputMode::parse(&args.output)?;
            chat::run(chat::ChatCommand {
                prompt: args.prompt,
                prompt_stdin: args.prompt_stdin,
                model: args.model,
                output,
            })
            .await
        }
        Commands::Upload(args) => upload::run(upload::UploadCommand { path: args.path }).await,
        Commands::Session(args) => {
            let output = OutputMode::parse(&args.output)?;
            match args.command {
                SessionSubcommand::Show => session_commands::show(output).await,
                SessionSubcommand::Clear => session_commands::clear().await,
            }
        }
    }
}
