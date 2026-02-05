// src/ws_server.rs
use crate::types::{IncomingMessage, NfcCommand, OutgoingMessage};
use crossbeam_channel::Sender;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use warp::Filter;

pub async fn start_server(
    nfc_cmd_tx: Sender<NfcCommand>,
    mut nfc_event_rx: tokio::sync::broadcast::Receiver<OutgoingMessage>,
) {
    // Shared Broadcast Channel for WS Clients
    let (ws_tx, _) = broadcast::channel::<OutgoingMessage>(32);
    let ws_tx = Arc::new(ws_tx);

    // 1. Task to forward NFC Events -> All WS Clients
    let ws_tx_clone = ws_tx.clone();
    tokio::spawn(async move {
        while let Ok(msg) = nfc_event_rx.recv().await {
            let _ = ws_tx_clone.send(msg);
        }
    });

    // 2. Define WS Route (Matches root path "/")
    // Changed from warp::path("ws") to warp::path::end()
    let ws_route = warp::path::end()
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let nfc_cmd_tx = nfc_cmd_tx.clone();
            let ws_tx = ws_tx.clone();

            // Allow any origin (Standard behavior for drop-in replacement)
            ws.on_upgrade(move |socket| handle_connection(socket, nfc_cmd_tx, ws_tx))
        });

    // Optional: Add CORS if your React app is strict, though usually not needed for raw WS
    let routes = ws_route.with(warp::cors().allow_any_origin());

    println!("WebSocket server running on ws://127.0.0.1:3500");
    warp::serve(routes).run(([127, 0, 0, 1], 3500)).await;
}

async fn handle_connection(
    ws: warp::ws::WebSocket,
    nfc_cmd_tx: Sender<NfcCommand>,
    ws_tx: Arc<broadcast::Sender<OutgoingMessage>>,
) {
    let (mut client_ws_tx, mut client_ws_rx) = ws.split();
    let mut rx_broadcast = ws_tx.subscribe();

    // Spawn task to send Broadcasts -> Client
    tokio::spawn(async move {
        while let Ok(msg) = rx_broadcast.recv().await {
            let json = serde_json::to_string(&msg).unwrap();
            if client_ws_tx
                .send(warp::ws::Message::text(json))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Handle incoming messages from Client
    while let Some(result) = client_ws_rx.next().await {
        if let Ok(msg) = result {
            if msg.is_text() {
                if let Ok(text) = msg.to_str() {
                    if let Ok(parsed) = serde_json::from_str::<IncomingMessage>(text) {
                        match parsed {
                            IncomingMessage::GET_READER_STATUS => {
                                let _ = nfc_cmd_tx.send(NfcCommand::CheckReaderStatus);
                            }
                            IncomingMessage::WRITE_DATA { payloads } => {
                                println!("incoming data; {:?}", payloads);

                                let _ = nfc_cmd_tx.send(NfcCommand::Write { payloads });
                            }
                        }
                    }
                }
            }
        }
    }
}
