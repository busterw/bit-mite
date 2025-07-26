use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum BencodeValue {
    Bytes(Vec<u8>),
    Integer(i64),
    List(Vec<BencodeValue>),
    Dictionary(BTreeMap<Vec<u8>, BencodeValue>),
}

#[derive(Debug, PartialEq)]
pub enum BencodeError {
    UnexpectedEof,
    InvalidInteger,
    InvalidStringLength,
    ExpectedCharacter(char),
    UnexpectedToken,
}

pub fn decode(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    if encoded_value.is_empty() {
        return Err(BencodeError::UnexpectedEof);
    }

    match encoded_value[0] {
        b'i' => decode_integer(encoded_value),
        b'l' => decode_list(encoded_value),
        b'd' => decode_dictionary(encoded_value),
        b'0'..=b'9' => decode_byte_string_value(encoded_value),
        _ => Err(BencodeError::UnexpectedToken),
    }
}

fn decode_byte_string_value(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    let (bytes, remaining) = decode_byte_string_slice(encoded_value)?;
    Ok((BencodeValue::Bytes(bytes.to_vec()), remaining))
}

fn decode_byte_string_slice(encoded_value: &[u8]) -> Result<(&[u8], &[u8]), BencodeError> {
    if let Some(colon_index) = encoded_value.iter().position(|&b| b == b':') {
        let len_slice = &encoded_value[..colon_index];
        let len_str =
            std::str::from_utf8(len_slice).map_err(|_| BencodeError::InvalidStringLength)?;
        let len = len_str
            .parse::<usize>()
            .map_err(|_| BencodeError::InvalidStringLength)?;
        let start = colon_index + 1;
        let end = start + len;
        if end > encoded_value.len() {
            return Err(BencodeError::UnexpectedEof);
        }
        Ok((&encoded_value[start..end], &encoded_value[end..]))
    } else {
        Err(BencodeError::ExpectedCharacter(':'))
    }
}

fn decode_integer(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    if let Some(end_index) = encoded_value.iter().position(|&b| b == b'e') {
        // Here we start from index 1 to skip the 'i'
        let num_slice = &encoded_value[1..end_index];
        let num_str = std::str::from_utf8(num_slice).map_err(|_| BencodeError::InvalidInteger)?;
        let number = num_str
            .parse::<i64>()
            .map_err(|_| BencodeError::InvalidInteger)?;
        // And here we skip the 'e' for the remainder
        Ok((
            BencodeValue::Integer(number),
            &encoded_value[end_index + 1..],
        ))
    } else {
        Err(BencodeError::ExpectedCharacter('e'))
    }
}

fn decode_list(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    let mut values = Vec::new();
    let mut remaining = &encoded_value[1..]; // Skip 'l'
    while !remaining.is_empty() && remaining[0] != b'e' {
        let (value, new_remaining) = decode(remaining)?;
        values.push(value);
        remaining = new_remaining;
    }
    if remaining.is_empty() {
        return Err(BencodeError::ExpectedCharacter('e'));
    }
    Ok((BencodeValue::List(values), &remaining[1..])) // Skip 'e'
}

fn decode_dictionary(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    let mut dict = BTreeMap::new();
    let mut remaining = &encoded_value[1..]; // Skip 'd'
    while !remaining.is_empty() && remaining[0] != b'e' {
        let (key, after_key) = decode_byte_string_slice(remaining)?;
        let (value, after_value) = decode(after_key)?;
        dict.insert(key.to_vec(), value);
        remaining = after_value;
    }
    if remaining.is_empty() {
        return Err(BencodeError::ExpectedCharacter('e'));
    }
    Ok((BencodeValue::Dictionary(dict), &remaining[1..])) // Skip 'e'
}
