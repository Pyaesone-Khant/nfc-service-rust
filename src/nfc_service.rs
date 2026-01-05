// src/nfc_service.rs
use crossbeam_channel::{Receiver, Sender};
use log::{error, info};
use pcsc::{Context, PNP_NOTIFICATION, Protocols, ReaderState, Scope, ShareMode, State, Error}; // <--- Changed here
use std::ffi::{CStr, CString};
use std::time::Duration;

use crate::types::{CARD_TYPE_MIFARE_1K, NfcCommand, OutgoingMessage};
use crate::{cards, ndef};

// Struct to track state and prevent spamming duplicate messages
struct ServiceState {
    reader_connected: bool,
    card_present: bool,
    last_data_read: Option<String>,
}

impl ServiceState {
    fn new() -> Self {
        Self {
            reader_connected: false,
            card_present: false,
            last_data_read: None,
        }
    }
}

pub fn run(tx: Sender<OutgoingMessage>, rx: Receiver<NfcCommand>) {
    info!("Starting NFC Service (Auto-Restart + Deduplication)...");

    // cache persists outside the recovery loop so we don't spam "Reader Connected" on every restart
    let mut state_cache = ServiceState::new();

    // --- OUTER RECOVERY LOOP ---
    // If PC/SC crashes, we break the inner loop and come back here to re-establish the context.
    loop {
        info!("Attempting to establish PC/SC Context...");

        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => {
                info!("PC/SC Context established successfully.");
                ctx
            }
            Err(err) => {
                error!("Failed to establish context: {}. Retrying in 3s...", err);
                if state_cache.reader_connected {
                    state_cache.reader_connected = false;
                    let _ = tx.send(OutgoingMessage::READER_ERROR {
                        error: "NFC Service Unavailable".into(),
                    });
                }
                std::thread::sleep(Duration::from_secs(3));
                continue; // Retry outer loop
            }
        };

        let mut readers_buf = [0; 2048];
        let mut reader_names: Vec<CString> = Vec::new();

        // Standard PnP tracker
        let mut reader_states = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];

        // 1. INITIAL SCAN (Fix for "Not working at all")
        // Force an update immediately so we don't have to wait for a plug/unplug event
        update_reader_list(&ctx, &mut reader_names, &mut reader_states, &mut readers_buf);
        
        let is_connected = !reader_names.is_empty();
        if is_connected {
            state_cache.reader_connected = true;
            let _ = tx.send(OutgoingMessage::READER_STATUS { success: true });
            info!("Initial Reader Found: {:?}", reader_names);
        } else {
             // If we restart and no reader is there, update cache
            state_cache.reader_connected = false;
        }

        // --- INNER PROCESSING LOOP ---
        loop {
            // 2. Wait for State Change
            // We use a timeout to allow checking for WebSocket commands periodically
            if let Err(err) = ctx.get_status_change(Duration::from_millis(500), &mut reader_states) {
                match err {
                    Error::Timeout => {
                        // Normal behavior, just continue
                    }
                    Error::ServiceStopped | Error::NoService => {
                        error!("CRITICAL PCSC ERROR: {}. Restarting service...", err);
                        break; // BREAK INNER LOOP -> Triggers Outer Loop Recovery
                    }
                    _ => {
                        error!("PCSC Error: {}. Retrying...", err);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            // 3. PROCESS COMMANDS
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    NfcCommand::Write { user_id } => {
                        println!("Received Write Command for user_id: {}", user_id);
                        handle_write_command(&ctx, &reader_names, &user_id, &tx);
                    }
                    NfcCommand::CheckReaderStatus => {
                        // We use the cached state because if the context is dead, 
                        // list_readers would fail anyway.
                        let _ = tx.send(OutgoingMessage::READER_STATUS {
                            success: state_cache.reader_connected,
                        });
                    }
                }
            }

            // 4. PROCESS PnP EVENTS (Hardware Changes)
            // Check if PnP (Index 0) changed
            if !reader_states.is_empty() && reader_states[0].event_state().intersects(State::CHANGED) {
                // Acknowledge change
                reader_states[0].sync_current_state();
                
                info!("Hardware change detected, refreshing list...");
                update_reader_list(&ctx, &mut reader_names, &mut reader_states, &mut readers_buf);

                let is_connected = !reader_names.is_empty();
                // DEDUPLICATION: Only send if status actually changed
                if is_connected != state_cache.reader_connected {
                    state_cache.reader_connected = is_connected;
                    let _ = tx.send(OutgoingMessage::READER_STATUS {
                        success: is_connected,
                    });
                }
            }

            // 5. PROCESS CARD EVENTS (Indices 1..n)
            for i in 1..reader_states.len() {
                // Safety check
                if i >= reader_states.len() { break; }

                let name = reader_names[i - 1].clone();
                let rs = &reader_states[i];

                if rs.event_state().intersects(State::CHANGED) {
                    let current = rs.event_state();
                    let previous = rs.current_state();

                    let is_present = current.intersects(State::PRESENT);
                    let was_present = previous.intersects(State::PRESENT);

                    // Sync state so we don't process this again
                    reader_states[i].sync_current_state();

                    // CASE A: Card Inserted
                    if is_present && !was_present {
                        info!("Card Inserted on {:?}", name);
                        // DEDUPLICATION: Only read if we didn't think a card was there
                        if !state_cache.card_present {
                            state_cache.card_present = true;
                            handle_card_insertion(&ctx, &name, &tx, &mut state_cache);
                        }
                    }

                    // CASE B: Card Removed
                    if !is_present && was_present {
                        info!("Card Removed from {:?}", name);
                        if state_cache.card_present {
                            state_cache.card_present = false;
                            state_cache.last_data_read = None; // Reset data cache so we can read same card again
                            let _ = tx.send(OutgoingMessage::CARD_STATUS {
                                success: false,
                                message: "Card removed!".into(),
                            });
                        }
                    }
                }
            }
        } // End Inner Loop

        // If we reach here, the inner loop broke (crash). 
        // Reset non-essential cache, but keep 'last_data_read' if you want.
        state_cache.reader_connected = false;
        state_cache.card_present = false;
        
        info!("Service loop exited. restarting in 1 second...");
        std::thread::sleep(Duration::from_secs(1));
    } // End Outer Loop
}

// --- HELPER FUNCTIONS ---

fn update_reader_list(
    ctx: &Context,
    reader_names: &mut Vec<CString>,
    reader_states: &mut Vec<ReaderState>,
    buf: &mut [u8],
) {
    match ctx.list_readers(buf) {
        Ok(iter) => {
            *reader_names = iter.map(|name| CString::from(name)).collect();

            // Reset states, keeping PnP at index 0
            reader_states.truncate(1);

            for name in reader_names.iter() {
                // Add new readers with UNAWARE state to force a check next loop
                reader_states.push(ReaderState::new(name.clone(), State::UNAWARE));
            }
        }
        Err(_) => {
            reader_names.clear();
            reader_states.truncate(1);
        }
    }
}

fn handle_card_insertion(
    ctx: &Context,
    reader_name: &CStr,
    tx: &Sender<OutgoingMessage>,
    cache: &mut ServiceState,
) {
    let _ = tx.send(OutgoingMessage::CARD_STATUS {
        success: true,
        message: "Card detected!".into(),
    });

    match ctx.connect(reader_name, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => {
            let mut names_buf = [0u8; 128];
            let mut atr_buf = [0u8; 64];
            let card_type = match card.status2(&mut names_buf, &mut atr_buf) {
                Ok(status) => {
                    let atr = status.atr();
                    if let Some(last) = atr.last() {
                        format!("{:x}", last)
                    } else {
                        "unknown".into()
                    }
                }
                Err(_) => "unknown".into(),
            };

            let data_res = if card_type == CARD_TYPE_MIFARE_1K {
                cards::read_mifare(&card)
            } else {
                cards::read_ntag(&card)
            };

            match data_res {
                Ok(raw) => match ndef::decode_ndef_text(&raw) {
                    Ok(text) => {
                        // DEDUPLICATION: Only send data if it changed
                        if cache.last_data_read.as_ref() != Some(&text) {
                            cache.last_data_read = Some(text.clone());
                            let _ = tx.send(OutgoingMessage::DATA_READ_SUCCESS { data: text });
                        }
                    }
                    Err(_) => {
                        // Optional: Deduplicate error messages too if desired
                        let _ = tx.send(OutgoingMessage::DATA_READ_ERROR {
                            error: "Empty/Non-NDEF".into(),
                        });
                    }
                },
                Err(e) => {
                    let _ = tx.send(OutgoingMessage::DATA_READ_ERROR { error: e });
                }
            }
        }
        Err(e) => error!("Failed to connect to card: {}", e),
    }
}

fn handle_write_command(
    ctx: &Context,
    reader_names: &[CString],
    user_id: &str,
    tx: &Sender<OutgoingMessage>,
) {

    println!("Starting write process for user_id: {}", user_id);
    if reader_names.is_empty() {
        let _ = tx.send(OutgoingMessage::DATA_WRITE_ERROR {
            error: "No reader connected".into(),
        });
        return;
    }

    println!("Attempting to write to card on available readers...");

    let mut success = false;
    for name in reader_names {
        if let Ok(card) = ctx.connect(name, ShareMode::Shared, Protocols::ANY) {
            let mut names_buf = [0u8; 128];
            let mut atr_buf = [0u8; 64];
            let card_type = match card.status2(&mut names_buf, &mut atr_buf) {
                Ok(status) => {
                    let atr = status.atr();
                    if let Some(last) = atr.last() {
                        format!("{:x}", last)
                    } else {
                        "unknown".into()
                    }
                }
                Err(_) => continue,
            };

            let ndef_msg = ndef::encode_ndef_message(user_id);
            let tlv_data = ndef::wrap_in_tlv(&ndef_msg);

            let write_res = if card_type == CARD_TYPE_MIFARE_1K {
                cards::write_mifare(&card, &tlv_data)
            } else {
                cards::write_ntag(&card, &tlv_data)
            };

            match write_res {
                Ok(_) => {
                    println!("Data written successfully to card.");
                    let _ = tx.send(OutgoingMessage::DATA_WRITE_SUCCESS {
                        message: "Data Written Successfully!".into(),
                    });
                    success = true;
                }
                Err(e) => {
                    println!("Failed to write data to card: {}", e);
                    let _ = tx.send(OutgoingMessage::DATA_WRITE_ERROR { error: e });
                    success = true;
                }
            }
            break;
        }
    }

    if !success {
        let _ = tx.send(OutgoingMessage::DATA_WRITE_ERROR {
            error: "No card found on reader".into(),
        });
    }
}
