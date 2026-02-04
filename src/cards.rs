// src/cards.rs
use crate::apdu;
use pcsc::Card;

// Keys from the JS file
pub const COMMON_KEYS: [[u8; 6]; 8] = [
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5],
    [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD],
    [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A],
    [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
];

// Blocks to read (skipping trailers)
pub const MIFARE_BLOCKS: [u8; 45] = [
    4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 36,
    37, 38, 40, 41, 42, 44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62,
];

pub fn read_mifare(card: &Card) -> Result<Vec<u8>, String> {
    let mut full_data = Vec::new();

    for &block in MIFARE_BLOCKS.iter() {
        // Authenticate new sector (every 4th block starting at 0, 4, 8...)
        if block % 4 == 0 {
            let mut auth_success = false;
            // Try to find a working key
            for key in COMMON_KEYS.iter() {
                if apdu::load_key(card, key).is_ok() {
                    // Try Key A (0x60)
                    if apdu::authenticate(card, block, 0x60).is_ok() {
                        auth_success = true;
                        break;
                    }
                    // Try Key B (0x61)
                    if apdu::authenticate(card, block, 0x61).is_ok() {
                        auth_success = true;
                        break;
                    }
                }
            }
            if !auth_success {
                return Err(format!("Auth failed for sector {}", block / 4));
            }
        }

        match apdu::read_binary(card, block, 16) {
            Ok(data) => {
                // Check if empty (JS logic: if empty, stop)
                if data.iter().all(|&b| b == 0x00) {
                    break;
                }
                full_data.extend(data);
            }
            Err(_) => break, // Stop reading on error
        }
    }
    Ok(full_data)
}

pub fn read_ntag(card: &Card) -> Result<Vec<u8>, String> {
    let mut full_data = Vec::new();
    // JS reads block 4 to 225
    for block in 4..226 {
        // NTAG Read sends 16 bytes usually (4 pages)
        match apdu::read_binary(card, block, 16) {
            Ok(data) => {
                if data.iter().all(|&b| b == 0x00) {
                    break;
                }
                full_data.extend(data);
            }
            Err(_) => break,
        }
    }
    Ok(full_data)
}

pub fn write_mifare(card: &Card, data: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    let mut current_block = 4;

    while offset < data.len() {
        // Skip trailers
        if (current_block + 1) % 4 == 0 {
            current_block += 1;
            continue;
        }

        // Authenticate Sector
        if current_block % 4 == 0 {
            let mut auth_success = false;
            for key in COMMON_KEYS.iter() {
                if apdu::load_key(card, key).is_ok() {
                    // We default to trying Key A for write auth usually, or same logic as read
                    if apdu::authenticate(card, current_block, 0x60).is_ok() {
                        auth_success = true;
                        break;
                    }
                }
            }
            if !auth_success {
                return Err("Write Auth Failed".to_string());
            }
        }

        // Chunking 16 bytes
        let bytes_left = data.len() - offset;
        let copy_len = std::cmp::min(16, bytes_left);
        let mut chunk = vec![0u8; 16]; // Pad with 0s
        chunk[0..copy_len].copy_from_slice(&data[offset..offset + copy_len]);

        apdu::update_binary(card, current_block, &chunk)?;

        offset += 16;
        current_block += 1;
    }
    Ok(())
}

pub fn write_ntag(card: &Card, data: &[u8]) -> Result<(), String> {
    // NTAG writes 4 bytes (1 page) at a time
    // Pad to multiple of 4
    let mut padded_data = data.to_vec();
    while padded_data.len() % 4 != 0 {
        padded_data.push(0x00);
    }

    let mut current_block = 4;
    for chunk in padded_data.chunks(4) {
        apdu::update_binary(card, current_block, chunk)?;
        current_block += 1;
    }
    Ok(())
}

pub fn read_ntag_v2(card: &Card) -> Result<Vec<u8>, String> {
    // 1. Read the first NDEF page (usually Page 4) to find the length
    let initial_data = apdu::read_binary(card, 4, 16)
        .map_err(|e| format!("Failed to read start of NDEF: {}", e))?;

    if initial_data[0] != 0x03 {
        return Err("No NDEF container found (Tag 0x03 missing)".into());
    }

    // 2. Determine Length (Handle 1-byte or 3-byte length)
    let (ndef_len, header_offset) = if initial_data[1] == 0xFF {
        let len = ((initial_data[2] as usize) << 8) | (initial_data[3] as usize);
        (len, 4) // 3-byte length starts at index 4
    } else {
        (initial_data[1] as usize, 2) // 1-byte length starts at index 2
    };

    println!("NDEF Message Length: {} bytes", ndef_len);

    // 3. Read the rest of the data based on ndef_len
    // (You already have some in initial_data, but for simplicity,
    // we can read the full range and slice it)
    let mut full_data = Vec::new();
    let total_pages_to_read = (ndef_len + header_offset + 3) / 4; // round up to pages

    for block in 4..(4 + total_pages_to_read) {
        match apdu::read_binary(card, block as u8, 4) {
            Ok(data) => full_data.extend(data),
            Err(_) => break,
        }
    }

    // 4. Return only the NDEF payload (stripping TLV header)
    if full_data.len() >= (header_offset + ndef_len) {
        Ok(full_data[header_offset..(header_offset + ndef_len)].to_vec())
    } else {
        Err("Incomplete read: card ended before NDEF length reached".into())
    }
}
