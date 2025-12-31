// src/ndef.rs
use std::str;

// Basic NDEF Text Record Wrapper
pub fn create_text_record_payload(text: &str) -> Vec<u8> {
    let lang = b"en";
    let lang_len = lang.len() as u8;
    let text_bytes = text.as_bytes();

    let mut payload = Vec::new();
    // Status byte: UTF-8 (bit 7=0) | Lang length (bits 0-5)
    payload.push(lang_len);
    payload.extend_from_slice(lang);
    payload.extend_from_slice(text_bytes);
    payload
}

pub fn encode_ndef_message(text: &str) -> Vec<u8> {
    let payload = create_text_record_payload(text);

    // NDEF Header: MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001 (NFC Forum Well Known Type)
    // 0xD1 = 1101 0001
    let header = 0xD1;
    let type_field = b"T"; // 'T' for Text

    let mut record = Vec::new();
    record.push(header);
    record.push(type_field.len() as u8); // Type Length
    record.push(payload.len() as u8); // Payload Length (assuming short record < 255)
    record.extend_from_slice(type_field);
    record.extend_from_slice(&payload);

    record
}

pub fn wrap_in_tlv(ndef_bytes: &[u8]) -> Vec<u8> {
    let mut tlv = Vec::new();
    // T = 0x03 (NDEF Message)
    tlv.push(0x03);

    // L (Length)
    if ndef_bytes.len() < 255 {
        tlv.push(ndef_bytes.len() as u8);
    } else {
        // Simple implementation: we assume short messages for this user ID use case
        tlv.push(0xFF);
        // Real implementation would handle multi-byte length, but 1K/NTAG usually small
    }

    // V (Value)
    tlv.extend_from_slice(ndef_bytes);

    // Terminator
    tlv.push(0xFE);

    tlv
}

pub fn decode_ndef_text(buffer: &[u8]) -> Result<String, String> {
    // 1. Find NDEF TLV (0x03)
    let start = buffer
        .iter()
        .position(|&b| b == 0x03)
        .ok_or("No NDEF TLV found")?;

    // Safety check for length index
    if start + 1 >= buffer.len() {
        return Err("Invalid buffer length".to_string());
    }

    let len = buffer[start + 1] as usize;
    let start_data = start + 2;

    if start_data + len > buffer.len() {
        return Err("Incomplete data".to_string());
    }

    let ndef_msg = &buffer[start_data..start_data + len];

    // 2. Parse NDEF Record (Assuming single Text Record for this specific use case)
    if ndef_msg.is_empty() {
        return Err("Empty NDEF".to_string());
    }

    // Skip Header (byte 0) and Type Length (byte 1)
    if ndef_msg.len() < 3 {
        return Err("Invalid NDEF Header".to_string());
    }
    let _header = ndef_msg[0];
    let type_len = ndef_msg[1] as usize;
    let payload_len = ndef_msg[2] as usize;

    // Calculate offsets
    let type_start = 3;
    let payload_start = type_start + type_len;

    if payload_start + payload_len > ndef_msg.len() {
        return Err("Invalid payload structure".to_string());
    }

    let payload = &ndef_msg[payload_start..payload_start + payload_len];

    // 3. Decode Text Payload
    if payload.is_empty() {
        return Err("Empty Payload".to_string());
    }

    let status_byte = payload[0];
    let lang_len = (status_byte & 0x3F) as usize;

    let text_start = 1 + lang_len;
    if text_start > payload.len() {
        return Err("Invalid Text Payload".to_string());
    }

    let text_bytes = &payload[text_start..];

    str::from_utf8(text_bytes)
        .map(|s| s.to_string())
        .map_err(|_| "UTF-8 Decode Error".to_string())
}
