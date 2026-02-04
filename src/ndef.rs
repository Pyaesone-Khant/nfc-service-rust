// src/ndef.rs
use std::str;

use crate::types::{NDEFType, NdefPayload, NdefRecord};

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

pub fn encode_single_record_ndef(
    content: &str,
    data_type: &NDEFType,
    mb: bool,
    me: bool,
) -> Vec<u8> {
    let mut record = Vec::new();

    // 1. Determine TNF and Type string
    let (tnf, type_string) = match data_type {
        NDEFType::TEXT => (0x01, b"T".to_vec()), // TNF 1: Well-Known Type
        NDEFType::URL => (0x01, b"U".to_vec()),  // TNF 1: Well-Known Type
        NDEFType::APP => (0x04, b"android.com:pkg".to_vec()), // TNF 4: External
    };

    // 2. Prepare Payload
    let mut payload = Vec::new();
    match data_type {
        NDEFType::TEXT => {
            // Text Record: [Status Byte] + [Lang Code] + [Text]
            let lang_code = b"en";
            let status_byte = lang_code.len() as u8; // Bit 7=0 (UTF-8), Bits 5-0 = lang length
            payload.push(status_byte);
            payload.extend_from_slice(lang_code);
            payload.extend_from_slice(content.as_bytes());
        }
        NDEFType::URL => {
            // URL Record: [Prefix Code] + [URL]
            // 0x04 = "https://www." (Common for URLs)
            // You can make this dynamic, but 0x00 means "No Prefix"
            payload.push(0x00);
            payload.extend_from_slice(content.as_bytes());
        }
        NDEFType::APP => {
            // Android App Record: Just the package name
            payload.extend_from_slice(content.as_bytes());
        }
    }

    // 3. Construct the Header (Flags)
    // Bit 7: MB, Bit 6: ME, Bit 5: CF(0), Bit 4: SR(1), Bit 3: IL(0), Bits 2-0: TNF
    let mut header = tnf; // Start with TNF bits
    if mb {
        header |= 0x80;
    } // Set MB bit
    if me {
        header |= 0x40;
    } // Set ME bit
    header |= 0x10; // Set SR (Short Record) bit - assuming payload < 255 bytes

    // 4. Build the Record Buffer
    record.push(header);
    record.push(type_string.len() as u8); // Type Length
    record.push(payload.len() as u8); // Payload Length (Works for SR=1)
    record.extend(type_string); // Record Type
    record.extend(payload); // Payload Data

    record
}

pub fn encode_multi_record_ndef(payloads: &[NdefPayload]) -> Vec<u8> {
    let mut full_message = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let mb = i == 0;
        let me = i == payloads.len() - 1;
        full_message.extend(encode_single_record_ndef(&p.content, &p.data_type, mb, me));
    }
    // Now wrap this in the TLV for the card
    wrap_in_tlv(&full_message)
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

pub fn parse_ndef_records(data: &[u8]) -> Result<Vec<NdefRecord>, String> {
    let mut records = Vec::new();
    let mut cursor = 0;

    while cursor < data.len() {
        let header = data[cursor];
        let tnf = header & 0x07; // Last 3 bits
        let is_short_record = (header & 0x10) != 0; // SR flag
        let has_id = (header & 0x08) != 0; // IL flag
        let is_me = (header & 0x40) != 0; // Message End flag

        cursor += 1;

        // 1. Get Type Length
        let type_len = data[cursor] as usize;
        cursor += 1;

        // 2. Get Payload Length (1 byte for Short Record, 4 bytes otherwise)
        let payload_len = if is_short_record {
            let len = data[cursor] as usize;
            cursor += 1;
            len
        } else {
            let len = ((data[cursor] as usize) << 24)
                | ((data[cursor + 1] as usize) << 16)
                | ((data[cursor + 2] as usize) << 8)
                | (data[cursor + 3] as usize);
            cursor += 4;
            len
        };

        // 3. Get ID Length (if present)
        let id_len = if has_id {
            let len = data[cursor] as usize;
            cursor += 1;
            len
        } else {
            0
        };

        // 4. Extract Type
        let record_type = data[cursor..cursor + type_len].to_vec();
        cursor += type_len;

        // 5. Extract ID
        let id = if has_id {
            let val = data[cursor..cursor + id_len].to_vec();
            cursor += id_len;
            Some(val)
        } else {
            None
        };

        // 6. Extract Payload
        let payload = data[cursor..cursor + payload_len].to_vec();
        cursor += payload_len;

        let mut final_payload = payload;

        if tnf == 0x01 && record_type == b"T" {
            if !final_payload.is_empty() {
                let status_byte = final_payload[0];
                let lang_code_len = (status_byte & 0x3F) as usize; // Bit 5-0 is length

                // Ensure we don't out-of-bounds if the payload is malformed
                let header_size = 1 + lang_code_len;
                if final_payload.len() > header_size {
                    final_payload = final_payload[header_size..].to_vec();
                }
            }
        }

        records.push(NdefRecord {
            tnf,
            record_type,
            payload: final_payload,
            id,
        });

        if is_me {
            break;
        }
    }

    Ok(records)
}
