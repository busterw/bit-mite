use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BencodeValue {
    Bytes(Vec<u8>),
    Integer(i64),
    List(Vec<BencodeValue>),
    Dictionary(BTreeMap<Vec<u8>, BencodeValue>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BencodeError {
    UnexpectedEof,
    InvalidInteger,
    InvalidStringLength,
    ExpectedCharacter(char),
    UnexpectedToken,
}

fn decode_byte_string(encoded_value: &[u8]) -> Result<(Vec<u8>, &[u8]), BencodeError> {
    // Find the colon
    let colon_index = encoded_value
        .iter()
        .position(|&b| b == b':')
        .ok_or(BencodeError::ExpectedCharacter(':'))?;

    // The part before the colon is the length
    let length_str = std::str::from_utf8(&encoded_value[..colon_index])
        .map_err(|_| BencodeError::InvalidStringLength)?;
    let length: usize = length_str
        .parse()
        .map_err(|_| BencodeError::InvalidStringLength)?;

    // The part after the colon is the string itself
    let start_of_string = colon_index + 1;
    let end_of_string = start_of_string + length;

    if end_of_string > encoded_value.len() {
        return Err(BencodeError::UnexpectedEof);
    }

    let byte_string = encoded_value[start_of_string..end_of_string].to_vec();
    let remaining = &encoded_value[end_of_string..];

    Ok((byte_string, remaining))
}

fn decode_integer(encoded_value: &[u8]) -> Result<(i64, &[u8]), BencodeError> {
    if encoded_value.is_empty() || encoded_value[0] != b'i' {
        return Err(BencodeError::ExpectedCharacter('i'));
    }

    let end_index = encoded_value
        .iter()
        .position(|&b| b == b'e')
        .ok_or(BencodeError::ExpectedCharacter('e'))?;

    let integer_str = std::str::from_utf8(&encoded_value[1..end_index])
        .map_err(|_| BencodeError::InvalidInteger)?;
    let integer: i64 = integer_str
        .parse()
        .map_err(|_| BencodeError::InvalidInteger)?;

    let remaining = &encoded_value[end_index + 1..];
    Ok((integer, remaining))
}

fn decode_list(encoded_value: &[u8]) -> Result<(Vec<BencodeValue>, &[u8]), BencodeError> {
    if encoded_value.is_empty() || encoded_value[0] != b'l' {
        return Err(BencodeError::ExpectedCharacter('l'));
    }

    let mut list = Vec::new();
    let mut current_slice = &encoded_value[1..];

    while !current_slice.is_empty() && current_slice[0] != b'e' {
        let (value, remaining) = decode(current_slice)?;
        list.push(value);
        current_slice = remaining;
    }

    if current_slice.is_empty() {
        return Err(BencodeError::ExpectedCharacter('e'));
    }

    Ok((list, &current_slice[1..]))
}

fn decode_dictionary(
    encoded_value: &[u8],
) -> Result<(BTreeMap<Vec<u8>, BencodeValue>, &[u8]), BencodeError> {
    if encoded_value.is_empty() || encoded_value[0] != b'd' {
        return Err(BencodeError::ExpectedCharacter('d'));
    }

    let mut dict = BTreeMap::new();
    let mut current_slice = &encoded_value[1..];

    while !current_slice.is_empty() && current_slice[0] != b'e' {
        let (key, remaining_after_key) = decode_byte_string(current_slice)?;
        let (value, remaining_after_value) = decode(remaining_after_key)?;
        dict.insert(key, value);
        current_slice = remaining_after_value;
    }

    if current_slice.is_empty() {
        return Err(BencodeError::ExpectedCharacter('e'));
    }

    Ok((dict, &current_slice[1..]))
}

pub fn decode(encoded_value: &[u8]) -> Result<(BencodeValue, &[u8]), BencodeError> {
    if encoded_value.is_empty() {
        return Err(BencodeError::UnexpectedEof);
    }
    match encoded_value[0] {
        b'0'..=b'9' => {
            let (bytes, remaining) = decode_byte_string(encoded_value)?;
            Ok((BencodeValue::Bytes(bytes), remaining))
        }
        b'i' => {
            let (integer, remaining) = decode_integer(encoded_value)?;
            Ok((BencodeValue::Integer(integer), remaining))
        }
        b'l' => {
            let (list, remaining) = decode_list(encoded_value)?;
            Ok((BencodeValue::List(list), remaining))
        }
        b'd' => {
            let (dict, remaining) = decode_dictionary(encoded_value)?;
            Ok((BencodeValue::Dictionary(dict), remaining))
        }
        _ => Err(BencodeError::UnexpectedToken),
    }
}

fn encode_byte_string(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = bytes.len().to_string().into_bytes();
    encoded.push(b':');
    encoded.extend_from_slice(bytes);
    encoded
}

fn encode_integer(int: i64) -> Vec<u8> {
    let mut encoded = b"i".to_vec();
    encoded.extend_from_slice(int.to_string().as_bytes());
    encoded.push(b'e');
    encoded
}

fn encode_list(list: &[BencodeValue]) -> Vec<u8> {
    let mut encoded = b"l".to_vec();
    for item in list {
        encoded.extend_from_slice(&item.to_bytes());
    }
    encoded.push(b'e');
    encoded
}

fn encode_dictionary(dict: &BTreeMap<Vec<u8>, BencodeValue>) -> Vec<u8> {
    let mut encoded = b"d".to_vec();
    for (key, value) in dict {
        encoded.extend_from_slice(&encode_byte_string(key));
        encoded.extend_from_slice(&value.to_bytes());
    }
    encoded.push(b'e');
    encoded
}

impl BencodeValue {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BencodeValue::Bytes(bytes) => encode_byte_string(bytes),
            BencodeValue::Integer(int) => encode_integer(*int),
            BencodeValue::List(list) => encode_list(list),
            BencodeValue::Dictionary(dict) => encode_dictionary(dict),
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, BencodeValue>> {
        if let Self::Dictionary(dict) = self {
            Some(dict)
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Self::Bytes(bytes) = self {
            Some(bytes)
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        self.as_bytes()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    pub fn as_integer(&self) -> Option<i64> {
        if let Self::Integer(int) = self {
            Some(*int)
        } else {
            None
        }
    }

    pub fn as_list(&self) -> Option<&Vec<BencodeValue>> {
        if let Self::List(list) = self {
            Some(list)
        } else {
            None
        }
    }
}
