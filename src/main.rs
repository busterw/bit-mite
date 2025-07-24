use serde_json;
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    // If encoded_value starts with a digit, it's a number

    if encoded_value.chars().next().unwrap().is_digit(10) {
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number = number_string.parse::<usize>().unwrap();

        let start = colon_index + 1;
        let end = start + number;

        let string = &encoded_value[start..end];
        let remaining = &encoded_value[end..]; // <- This is what you return

        return (serde_json::Value::String(string.to_string()), remaining);
    } else if encoded_value.chars().next().unwrap() == 'i' {
        let integer_end_index = encoded_value.find('e').unwrap();
        let number_as_isize = encoded_value[1..integer_end_index]
            .parse::<isize>()
            .unwrap();
        let remaining = &encoded_value[integer_end_index + 1..];
        return (serde_json::Value::Number(number_as_isize.into()), remaining);
    } else if encoded_value.chars().next().unwrap() == 'l' {
        let mut rest = &encoded_value[1..];
        let mut list = Vec::new();

        while !rest.starts_with('e') {
            let decoded_part = decode_bencoded_value(rest);
            list.push(decoded_part.0);
            rest = decoded_part.1;
        }
        rest = &rest[1..];
        return (serde_json::Value::Array(list), rest);
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

// Usage: your_program.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        eprintln!("Logs from your program will appear here!");

        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.0.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}