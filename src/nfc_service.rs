// src/nfc_service.rs
use crossbeam_channel::{Receiver, Sender};
use log::{error, info};
use pcsc::{Context, PNP_NOTIFICATION, Protocols, ReaderState, Scope, ShareMode, State}; // <--- Changed here
use std::ffi::{CStr, CString};
use std::time::Duration;

use crate::types::{CARD_TYPE_MIFARE_1K, CARD_TYPE_NTAG, NfcCommand, OutgoingMessage};
use crate::{cards, ndef};

pub fn run(tx: Sender<OutgoingMessage>, rx: Receiver<NfcCommand>) {
    info!("Starting NFC Service (Event Driven)...");

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to establish context: {}", err);
            let _ = tx.send(OutgoingMessage::READER_ERROR {
                error: err.to_string(),
            });
            return;
        }
    };

    let mut readers_buf = [0; 2048];
    let mut reader_names: Vec<CString> = Vec::new();

    // CORRECTED: Use PNP_NOTIFICATION() instead of Pn532::new()
    let mut reader_states = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];

    loop {
        // 1. Wait for State Change
        if let Err(err) = ctx.get_status_change(Duration::from_millis(500), &mut reader_states) {
            if err != pcsc::Error::Timeout {
                error!("PCSC Error: {}", err);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        }

        // 2. CHECK FOR COMMANDS
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                NfcCommand::Write { user_id } => {
                    println!("Received Write Command for user_id: {}", user_id);
                    handle_write_command(&ctx, &reader_names, &user_id, &tx);
                }
                NfcCommand::CheckReaderStatus => {
                    // Trigger a reader status check by refreshing the reader list
                    match ctx.list_readers(&mut readers_buf) {
                        Ok(iter) => {
                            reader_names = iter.map(|name| CString::from(name)).collect();
                            let _ = tx.send(OutgoingMessage::READER_STATUS {
                                success: reader_names.len() > 0,
                            });
                        }
                        Err(_) => {
                            reader_names.clear();
                            let _ = tx.send(OutgoingMessage::READER_STATUS { success: false });
                        }
                    }
                }
            }
        }

        // 3. PROCESS EVENTS
        let mut readers_changed = false;

        // Check PnP (Index 0)
        if reader_states[0].event_state().intersects(State::CHANGED) {
            info!("Hardware change detected");
            readers_changed = true;
            reader_states[0].sync_current_state();
        }

        // Check Readers (Indices 1..)
        for i in 1..reader_states.len() {
            let name = reader_names[i - 1].clone();
            let rs = &reader_states[i];

            if rs.event_state().intersects(State::CHANGED) {
                let current = rs.event_state();

                // Card Inserted
                if current.intersects(State::PRESENT)
                    && !rs.current_state().intersects(State::PRESENT)
                {
                    info!("Card Inserted on {:?}", name);
                    handle_card_insertion(&ctx, &name, &tx);
                }

                // Card Removed
                if current.intersects(State::EMPTY) && rs.current_state().intersects(State::PRESENT)
                {
                    info!("Card Removed from {:?}", name);
                    let _ = tx.send(OutgoingMessage::CARD_STATUS {
                        success: false,
                        message: "Card removed!".into(),
                    });
                }

                reader_states[i].sync_current_state();
            }
        }

        // 4. REFRESH LIST
        if readers_changed {
            match ctx.list_readers(&mut readers_buf) {
                Ok(iter) => {
                    reader_names = iter.map(|name| CString::from(name)).collect();
                    // FIX: Instead of moving index 0 out, we just truncate the vector
                    // This keeps the PnP state (index 0) and drops everything else.
                    reader_states.truncate(1);
                    for name in &reader_names {
                        // Remember to use .clone() here as discussed before
                        reader_states.push(ReaderState::new(name.clone(), State::UNAWARE));
                    }

                    let _ = tx.send(OutgoingMessage::READER_STATUS {
                        success: reader_names.len() > 0,
                    });
                }
                Err(_) => {
                    reader_names.clear();

                    // FIX: Same fix here
                    reader_states.truncate(1);

                    let _ = tx.send(OutgoingMessage::READER_STATUS { success: false });
                }
            }
        }
    }
}

fn handle_card_insertion(ctx: &Context, reader_name: &CStr, tx: &Sender<OutgoingMessage>) {
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
                        let _ = tx.send(OutgoingMessage::DATA_READ_SUCCESS { data: text });
                    }
                    Err(_) => {
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
    if reader_names.is_empty() {
        let _ = tx.send(OutgoingMessage::DATA_WRITE_ERROR {
            error: "No reader connected".into(),
        });
        return;
    }

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
                    let _ = tx.send(OutgoingMessage::DATA_WRITE_SUCCESS {
                        message: "Data Written Successfully!".into(),
                    });
                    success = true;
                }
                Err(e) => {
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
