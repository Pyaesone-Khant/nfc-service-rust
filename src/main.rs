mod apdu;
mod cards;
mod ndef;
mod nfc_service;
mod types;
mod ws;

use crossbeam_channel::unbounded;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("Starting NFC Rust Service...");

    // Channel: WS -> NFC (Commands)
    // We use Crossbeam (Sync) because NFC thread is blocking
    let (cmd_tx, cmd_rx) = unbounded::<types::NfcCommand>();

    // Channel: NFC -> WS (Events)
    // We use Tokio Broadcast for distribution to WS clients
    let (event_tx, event_rx) = broadcast::channel::<types::OutgoingMessage>(100);

    // Spawn NFC Thread (Blocking OS Thread)
    let event_tx_clone = event_tx.clone();
    std::thread::spawn(move || {
        // We need a bridge to convert sync sends to async broadcast
        // Simplified: The NFC service will send to a bridging channel?
        // Actually, broadcast::Sender::send is sync! So we can pass it directly.

        // Wait, tokio broadcast send is sync, but we need to feed it from the NFC thread.
        // Let's use a crossbeam channel to bridge NFC thread -> Main Async Task -> Broadcast

        let (bridge_tx, bridge_rx) = unbounded::<types::OutgoingMessage>();

        // Spawn the NFC logic
        std::thread::spawn(move || {
            nfc_service::run(bridge_tx, cmd_rx);
        });

        // Bridge Loop (Runs in this thread or main, let's keep it here to simplify)
        while let Ok(msg) = bridge_rx.recv() {
            let _ = event_tx_clone.send(msg);
        }
    });

    // Start WebSocket Server
    ws::start_server(cmd_tx, event_rx).await;
}
