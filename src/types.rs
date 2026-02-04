// src/types.rs
use serde::{Deserialize, Serialize};

// Messages sent TO the WebSocket client (Frontend)
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum OutgoingMessage {
    READER_STATUS { success: bool },
    CARD_STATUS { success: bool, message: String },
    DATA_READ_SUCCESS { data: String },
    DATA_READ_ERROR { error: String },
    DATA_WRITE_SUCCESS { message: String },
    DATA_WRITE_ERROR { error: String },
    READER_ERROR { error: String },
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum NDEFType {
    TEXT,
    URL,
    APP,
}

#[derive(Debug)]
pub struct NdefRecord {
    pub tnf: u8, // Type Name Format (How to interpret the type)
    pub record_type: Vec<u8>,
    pub payload: Vec<u8>,
    pub id: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct NdefPayload {
    pub data_type: NDEFType,
    pub content: String,
}

// Messages received FROM the WebSocket client
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum IncomingMessage {
    GET_READER_STATUS,
    WRITE_DATA { data_type: String, user_id: String },
}

// Internal commands sent from WS Server -> NFC Thread
#[derive(Debug)]
pub enum NfcCommand {
    Write { user_id: String },
    CheckReaderStatus,
}

pub const CARD_TYPE_MIFARE_1K: &str = "6a"; // MIFARE Classic 1K
pub const CARD_TYPE_NTAG: &str = "68"; // NTAG215/Ultralight
