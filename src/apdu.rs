// src/apdu.rs
use pcsc::Card;

// Load Authentication Keys into Reader Memory (Location 0x00 or 0x20)
// ACR122U standard: FF 82 00 key_num 06 [KEY]
pub fn load_key(card: &Card, key: &[u8; 6]) -> Result<(), String> {
    let mut apdu = vec![0xFF, 0x82, 0x00, 0x00, 0x06];
    apdu.extend_from_slice(key);

    let mut recv_buffer = [0u8; 256];
    match card.transmit(&apdu, &mut recv_buffer) {
        Ok(resp) => {
            // 0x90 0x00 is Success
            if resp.len() >= 2 && resp[resp.len() - 2] == 0x90 && resp[resp.len() - 1] == 0x00 {
                Ok(())
            } else {
                Err(format!("Load Key Failed: {:02X?}", resp))
            }
        }
        Err(e) => Err(format!("Transmit Error: {}", e)),
    }
}

// Authenticate Block
// CMD: FF 86 00 00 05 01 00 Block KeyType KeyNumber
// KeyType: 0x60 (A), 0x61 (B)
pub fn authenticate(card: &Card, block: u8, key_type: u8) -> Result<(), String> {
    let apdu = [
        0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, 0x00,
    ];

    let mut recv_buffer = [0u8; 256];
    match card.transmit(&apdu, &mut recv_buffer) {
        Ok(resp) => {
            if resp.len() >= 2 && resp[resp.len() - 2] == 0x90 && resp[resp.len() - 1] == 0x00 {
                Ok(())
            } else {
                Err("Auth Failed".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn read_binary(card: &Card, block: u8, length: u8) -> Result<Vec<u8>, String> {
    // Read: FF B0 00 Block Len
    let apdu = [0xFF, 0xB0, 0x00, block, length];
    let mut recv_buffer = [0u8; 256];

    match card.transmit(&apdu, &mut recv_buffer) {
        Ok(resp) => {
            if resp.len() >= 2 && resp[resp.len() - 2] == 0x90 && resp[resp.len() - 1] == 0x00 {
                // Return data without status word
                Ok(resp[0..resp.len() - 2].to_vec())
            } else {
                Err("Read Failed".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn update_binary(card: &Card, block: u8, data: &[u8]) -> Result<(), String> {
    // Write: FF D6 00 Block Len [Data]
    let mut apdu = vec![0xFF, 0xD6, 0x00, block, data.len() as u8];
    apdu.extend_from_slice(data);

    let mut recv_buffer = [0u8; 256];
    match card.transmit(&apdu, &mut recv_buffer) {
        Ok(resp) => {
            if resp.len() >= 2 && resp[resp.len() - 2] == 0x90 && resp[resp.len() - 1] == 0x00 {
                Ok(())
            } else {
                Err("Write Failed".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
