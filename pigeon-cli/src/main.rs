// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Pigeon contributors.

//! `pigeon`: an end-to-end-encrypted Pigeon client for any terminal.
//!
//! It shares `pigeon-core` (Olm via vodozemac) and the relay mailbox protocol
//! with the iOS app, so a terminal and a phone can message each other. It does
//! direct messages over relays; the Bluetooth mesh and MLS groups stay on the
//! phone for now.

mod card;
mod engine;
mod identity;
mod relay;
mod vault;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::engine::{Contact, Delivery, Engine, Notice, Relationship};
use crate::relay::{Event, Hub};
use crate::vault::{KdfCost, Vault};

const DEFAULT_RELAY: &str = "wss://relay.pigeonwire.app/ws";

#[derive(Parser)]
#[command(
    name = "pigeon",
    version,
    about = "End-to-end-encrypted Pigeon messaging in your terminal"
)]
struct Cli {
    /// Where the sealed vault lives.
    #[arg(long, global = true, env = "PIGEON_HOME")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity (asks for a passphrase that seals it).
    Init {
        /// The display name contacts see on your card.
        #[arg(long)]
        name: String,
        /// Relay(s) you receive on. Repeat for more than one.
        #[arg(long = "relay", default_value = DEFAULT_RELAY)]
        relays: Vec<String>,
    },
    /// Print your contact link (paste it into the app's Add Contact screen).
    Card {
        /// Print the raw base64 QR payload instead of a link.
        #[arg(long)]
        raw: bool,
    },
    /// Add a contact from their link, QR payload, or base64 card.
    Add {
        card: String,
        /// You both added each other in person; skip the message-request step.
        #[arg(long)]
        mutual: bool,
    },
    /// List contacts and pending requests.
    Contacts,
    /// Accept an incoming message request.
    Accept { contact: String },
    /// Show the safety number to compare with a contact in person.
    Safety {
        contact: String,
        /// Record that you compared it and it matched.
        #[arg(long)]
        verified: bool,
    },
    /// Send one message and wait until the relay has stored it.
    Send {
        contact: String,
        message: Vec<String>,
    },
    /// Print conversation history with a contact.
    History { contact: String },
    /// Receive messages and print them as they arrive.
    Listen,
    /// Interactive chat (the default when no command is given).
    Chat { contact: Option<String> },
    /// Show or replace the relays you receive on.
    Relays { urls: Vec<String> },
}

#[tokio::main]
async fn main() {
    // A process-wide rustls provider is required before the first `wss://`
    // connection; `Err` only means one was already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("pigeon: {error}");
        std::process::exit(1);
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

async fn run(cli: Cli) -> Result<()> {
    let home = cli.home.unwrap_or_else(default_home);
    let command = cli.command.unwrap_or(Command::Chat { contact: None });

    if let Command::Init { name, relays } = command {
        if !relays.iter().all(|url| card::is_valid_relay_url(url)) {
            return Err("relay URLs must start with ws:// or wss://".into());
        }
        let passphrase = new_passphrase()?;
        eprintln!("Sealing your identity (this takes a moment)…");
        let vault = Vault::create(&home, &passphrase, KdfCost::default())?;
        let engine = Engine::create(vault, &name, relays)?;
        println!(
            "Created identity for {} in {}",
            engine.name(),
            home.display()
        );
        println!("\nShare this link so others can add you:\n");
        println!("{}", card::share_link(&engine.card()?));
        return Ok(());
    }

    let passphrase = existing_passphrase()?;
    let engine = Engine::open(Vault::open(&home, &passphrase)?)?;
    drop(passphrase);
    let engine = Arc::new(Mutex::new(engine));

    match command {
        Command::Init { .. } => unreachable!(),
        Command::Card { raw } => {
            let card = engine.lock().unwrap().card()?;
            println!(
                "{}",
                if raw {
                    card::qr_payload(&card)
                } else {
                    card::share_link(&card)
                }
            );
        }
        Command::Add { card, mutual } => {
            let contact = engine.lock().unwrap().add_contact(&card, mutual)?;
            println!("Added {} ({}).", contact.name, short(&contact.identity));
            if contact.relays.is_empty() {
                println!(
                    "Their card advertises no verified relay, so they can't be reached from here."
                );
            } else if !mutual {
                println!(
                    "Your first message goes out as a request; they can reply once they accept."
                );
            }
            println!(
                "Compare safety numbers in person with `pigeon safety {}`.",
                contact.name
            );
        }
        Command::Contacts => print_contacts(&engine.lock().unwrap()),
        Command::Accept { contact } => {
            let hub = start_hub(&engine, false);
            let contact = engine.lock().unwrap().resolve(&contact)?;
            engine.lock().unwrap().accept(&contact)?;
            println!("Accepted {}.", contact.name);
            flush_outbox(&hub).await;
        }
        Command::Safety { contact, verified } => {
            let mut guard = engine.lock().unwrap();
            let contact = guard.resolve(&contact)?;
            println!(
                "Safety number with {}:\n\n  {}\n",
                contact.name,
                guard.safety_number(&contact)
            );
            println!(
                "It must match the number on {}'s screen exactly.",
                contact.name
            );
            if verified {
                guard.mark_verified(&contact.identity)?;
                println!("Marked {} as verified.", contact.name);
            }
        }
        Command::Send { contact, message } => {
            let hub = start_hub(&engine, false);
            let contact = engine.lock().unwrap().resolve(&contact)?;
            engine
                .lock()
                .unwrap()
                .send_text(&contact, &message.join(" "))?;
            hub.kick();
            flush_outbox(&hub).await;
        }
        Command::History { contact } => {
            let guard = engine.lock().unwrap();
            let contact = guard.resolve(&contact)?;
            for entry in guard.history(&contact.identity) {
                println!("{}", format_entry(&contact, entry));
            }
        }
        Command::Listen => {
            let (hub, mut events) = start_session(&engine);
            hub.start(true);
            while let Some(event) = events.recv().await {
                print_event(&event);
            }
        }
        Command::Chat { contact } => interactive(engine, contact).await?,
        Command::Relays { urls } => {
            let mut guard = engine.lock().unwrap();
            if urls.is_empty() {
                for url in guard.relays() {
                    println!("{url}");
                }
            } else {
                guard.set_relays(urls)?;
                println!("Relays updated. Share your new card: `pigeon card`.");
            }
        }
    }
    Ok(())
}

fn start_session(engine: &Arc<Mutex<Engine>>) -> (Hub, mpsc::UnboundedReceiver<Event>) {
    let (tx, rx) = mpsc::unbounded_channel();
    (Hub::new(engine.clone(), tx), rx)
}

fn start_hub(engine: &Arc<Mutex<Engine>>, receive: bool) -> Hub {
    let (hub, mut events) = start_session(engine);
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let Event::Status(status) = event {
                eprintln!("  · {status}");
            }
        }
    });
    hub.start(receive);
    hub
}

/// Waits (bounded) until every queued deposit has a relay receipt.
async fn flush_outbox(hub: &Hub) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while hub.pending_count() > 0 {
        if tokio::time::Instant::now() > deadline {
            eprintln!(
                "Still queued after 30s; it stays sealed in your vault and goes out next time Pigeon runs."
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!("Delivered to the relay.");
}

// MARK: - Interactive chat

async fn interactive(engine: Arc<Mutex<Engine>>, initial: Option<String>) -> Result<()> {
    let (hub, mut events) = start_session(&engine);
    hub.start(true);
    let mut current: Option<Contact> = match initial {
        Some(query) => Some(engine.lock().unwrap().resolve(&query)?),
        None => None,
    };
    println!(
        "Pigeon — signed in as {}. Type /help for commands.",
        engine.lock().unwrap().name()
    );
    if let Some(contact) = &current {
        open_chat(&engine, contact);
    }
    prompt(&current);

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                clear_prompt();
                print_event(&event);
                prompt(&current);
            }
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                match handle_line(&engine, &hub, &mut current, line.trim()) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(error) => println!("  ! {error}"),
                }
                prompt(&current);
            }
        }
    }
    let pending = hub.pending_count();
    if pending > 0 {
        println!("Delivering {pending} queued item(s) before exit…");
        flush_outbox(&hub).await;
    }
    Ok(())
}

/// Returns `true` to quit.
fn handle_line(
    engine: &Arc<Mutex<Engine>>,
    hub: &Hub,
    current: &mut Option<Contact>,
    line: &str,
) -> Result<bool> {
    if line.is_empty() {
        return Ok(false);
    }
    let Some(command) = line.strip_prefix('/') else {
        let Some(contact) = current.as_ref() else {
            println!("  Pick a conversation first: /chat <name>  (see /contacts)");
            return Ok(false);
        };
        engine.lock().unwrap().send_text(contact, line)?;
        hub.kick();
        return Ok(false);
    };
    let (name, rest) = command.split_once(' ').unwrap_or((command, ""));
    let rest = rest.trim();
    match name {
        "q" | "quit" | "exit" => return Ok(true),
        "h" | "help" => print_help(),
        "card" => println!("{}", card::share_link(&engine.lock().unwrap().card()?)),
        "contacts" | "c" => print_contacts(&engine.lock().unwrap()),
        "chat" | "open" => {
            let contact = engine.lock().unwrap().resolve(rest)?;
            open_chat(engine, &contact);
            *current = Some(contact);
        }
        "add" => {
            let (input, mutual) = match rest.strip_suffix("--mutual") {
                Some(input) => (input.trim(), true),
                None => (rest, false),
            };
            let contact = engine.lock().unwrap().add_contact(input, mutual)?;
            println!(
                "  Added {}. /chat {} to message them.",
                contact.name, contact.name
            );
        }
        "accept" => {
            let contact = engine.lock().unwrap().resolve(rest)?;
            engine.lock().unwrap().accept(&contact)?;
            hub.kick();
            println!("  Accepted {}.", contact.name);
            if current
                .as_ref()
                .is_some_and(|c| c.identity == contact.identity)
            {
                *current = Some(engine.lock().unwrap().resolve(&contact.identity)?);
            }
        }
        "safety" => {
            let guard = engine.lock().unwrap();
            let contact = match rest {
                "" => current.clone().ok_or("usage: /safety <name>")?,
                query => guard.resolve(query)?,
            };
            println!(
                "  Safety number with {}: {}",
                contact.name,
                guard.safety_number(&contact)
            );
            println!("  If it matches their screen, run /verify {}", contact.name);
        }
        "verify" => {
            let mut guard = engine.lock().unwrap();
            let contact = guard.resolve(rest)?;
            guard.mark_verified(&contact.identity)?;
            println!("  Marked {} as verified.", contact.name);
        }
        "rename" => {
            let contact = current.clone().ok_or("open a chat first")?;
            engine.lock().unwrap().rename(&contact.identity, rest)?;
            *current = Some(engine.lock().unwrap().resolve(&contact.identity)?);
        }
        "history" => {
            if let Some(contact) = current.as_ref() {
                open_chat(engine, contact);
            }
        }
        "status" => {
            let online = hub.online_relays();
            if online.is_empty() {
                println!("  Not connected to any of your relays yet.");
            } else {
                for url in online {
                    println!("  receiving on {}", relay::host(&url));
                }
            }
            println!(
                "  {} item(s) waiting for a relay receipt",
                hub.pending_count()
            );
        }
        other => println!("  Unknown command /{other}. Type /help."),
    }
    Ok(false)
}

fn open_chat(engine: &Arc<Mutex<Engine>>, contact: &Contact) {
    let guard = engine.lock().unwrap();
    let current = guard
        .resolve(&contact.identity)
        .unwrap_or_else(|_| contact.clone());
    println!("── {} {}", current.name, badge(&current));
    let history = guard.history(&current.identity);
    for entry in &history[history.len().saturating_sub(20)..] {
        println!("{}", format_entry(&current, entry));
    }
    match current.relationship {
        Relationship::IncomingRequest => {
            println!("  Message request. /accept {} to reply.", current.name)
        }
        Relationship::OutgoingRequest => {
            println!("  Waiting for {} to accept your request.", current.name)
        }
        Relationship::Contact => {}
    }
}

fn print_help() {
    println!(
        "  <text>              send to the open conversation
  /chat <name>        open a conversation
  /contacts           list contacts and requests
  /add <link> [--mutual]  add a contact from their link
  /accept <name>      accept a message request
  /card               show your contact link
  /safety [name]      show the safety number to compare in person
  /verify <name>      mark a contact verified after comparing
  /rename <new name>  rename the open contact
  /history            reprint the open conversation
  /status             relay connection status
  /quit               leave (queued messages are kept)"
    );
}

fn print_contacts(engine: &Engine) {
    let contacts = engine.contacts();
    if contacts.is_empty() {
        println!("No contacts yet. Share `pigeon card`, or add someone with `pigeon add <link>`.");
        return;
    }
    for contact in contacts {
        println!(
            "  {:<24} {} {}",
            contact.name,
            short(&contact.identity),
            badge(contact)
        );
    }
}

fn badge(contact: &Contact) -> &'static str {
    match (contact.relationship, contact.verified) {
        (Relationship::IncomingRequest, _) => "[request]",
        (Relationship::OutgoingRequest, _) => "[awaiting acceptance]",
        (Relationship::Contact, true) => "[verified]",
        (Relationship::Contact, false) => "[not verified]",
    }
}

fn format_entry(contact: &Contact, entry: &engine::HistoryEntry) -> String {
    let who = if entry.mine {
        "you"
    } else {
        contact.name.as_str()
    };
    if entry.system {
        return format!("  · {} {}", who, entry.text);
    }
    let status = match entry.delivery {
        Some(Delivery::Delivered) => " ✓✓",
        Some(Delivery::Sent) => " ✓",
        None => "",
    };
    format!("  {who}: {}{status}", entry.text)
}

fn print_event(event: &Event) {
    match event {
        Event::Notice(Notice::Message { from, text }) => println!("  {from}: {text}"),
        Event::Notice(Notice::Request { from, text }) => {
            println!("  [request] {from}: {text}\n  /accept {from} to reply.")
        }
        Event::Notice(Notice::Delivered { to }) => println!("  · delivered to {to}"),
        Event::Notice(Notice::Accepted { by }) => println!("  · {by} accepted your request"),
        Event::Notice(Notice::System { from, text }) => println!("  · {from} {text}"),
        Event::Status(status) => println!("  · {status}"),
    }
}

fn prompt(current: &Option<Contact>) {
    if !std::io::stdin().is_terminal() {
        return;
    }
    match current {
        Some(contact) => print!("{}> ", contact.name),
        None => print!("> "),
    }
    let _ = std::io::stdout().flush();
}

fn clear_prompt() {
    if std::io::stdout().is_terminal() {
        print!("\r\x1b[2K");
    }
}

fn short(identity: &str) -> String {
    identity.chars().take(8).collect()
}

fn default_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(
            || PathBuf::from(".pigeon"),
            |home| PathBuf::from(home).join(".pigeon"),
        )
}

/// `PIGEON_PASSPHRASE` exists for scripts and tests; interactive use prompts
/// without echo so the passphrase never lands in shell history.
fn existing_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(value) = std::env::var("PIGEON_PASSPHRASE") {
        return Ok(Zeroizing::new(value));
    }
    Ok(Zeroizing::new(rpassword::prompt_password("Passphrase: ")?))
}

fn new_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(value) = std::env::var("PIGEON_PASSPHRASE") {
        return Ok(Zeroizing::new(value));
    }
    let first = Zeroizing::new(rpassword::prompt_password("Choose a passphrase: ")?);
    if first.chars().count() < 8 {
        return Err("use a passphrase of at least 8 characters".into());
    }
    let second = Zeroizing::new(rpassword::prompt_password("Repeat it: ")?);
    if first != second {
        return Err("passphrases did not match".into());
    }
    Ok(first)
}
