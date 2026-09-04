#![forbid(unsafe_code)]

//! Offline deterministic password derivation.
//!
//! Version 3 is Destiny's modern, memory-hard format. Versions 2 and 1 are
//! frozen compatibility implementations of One Shall Pass and must never be
//! changed: changing either would rotate existing passwords.

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use std::{error::Error, fmt, net::IpAddr};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

const LEGACY_MIN_LENGTH: u8 = 8;
const V3_MIN_LENGTH: u8 = 12;
const MAX_LENGTH: u8 = 16;
const MAX_SYMBOLS: u8 = 3;
const MAX_SECURITY_BITS: u8 = 16;
const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const SYMBOL_ALPHABET: &[u8] = b"`~!@#$%^&*()-_+={}[]|;:,<>.?/";

/// These constants are part of the v3 format and must only change in a new
/// algorithm version.
pub const V3_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const V3_ARGON2_PASSES: u32 = 3;
pub const V3_ARGON2_LANES: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// Destiny v3: Argon2id v1.3, 64 MiB, three passes, four lanes.
    V3,
    /// Frozen One Shall Pass v2 compatibility mode.
    V2,
    /// Frozen original One Shall Pass v1 compatibility mode.
    LegacyV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Used only by v2/v1. V3's work factor is fixed by its version.
    pub security_bits: u8,
    pub generation: u32,
    pub length: u8,
    pub symbols: u8,
    pub algorithm: Algorithm,
}

impl Parameters {
    pub const fn defaults_for(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::V3 => Self {
                security_bits: 8,
                generation: 1,
                length: 16,
                symbols: 0,
                algorithm,
            },
            Algorithm::V2 => Self {
                security_bits: 8,
                generation: 1,
                length: 12,
                symbols: 0,
                algorithm,
            },
            Algorithm::LegacyV1 => Self {
                security_bits: 7,
                generation: 1,
                length: 12,
                symbols: 0,
                algorithm,
            },
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::defaults_for(Algorithm::V3)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeriveError {
    InvalidLength { value: u8, minimum: u8 },
    InvalidSymbols(u8),
    InvalidSecurityBits(u8),
    InvalidGeneration,
    InvalidEmail(String),
    InvalidHost(String),
    EmptyEmail,
    EmptyPassphrase,
    EmptyHost,
    KdfFailure,
    CounterExhausted,
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { value, minimum } => write!(
                f,
                "length must be between {minimum} and {MAX_LENGTH} for this algorithm, got {value}"
            ),
            Self::InvalidSymbols(value) => write!(
                f,
                "symbols must be between 0 and {MAX_SYMBOLS}, got {value}"
            ),
            Self::InvalidSecurityBits(value) => write!(
                f,
                "legacy security bits must be between 1 and {MAX_SECURITY_BITS}, got {value}"
            ),
            Self::InvalidGeneration => f.write_str("generation must be at least 1"),
            Self::InvalidEmail(reason) => write!(f, "invalid email: {reason}"),
            Self::InvalidHost(reason) => write!(f, "invalid host: {reason}"),
            Self::EmptyEmail => f.write_str("email must not be empty"),
            Self::EmptyPassphrase => f.write_str("master password must not be empty"),
            Self::EmptyHost => f.write_str("host must not be empty"),
            Self::KdfFailure => f.write_str("Argon2id key derivation failed"),
            Self::CounterExhausted => f.write_str("password search counter exhausted"),
        }
    }
}

impl Error for DeriveError {}

pub fn validate_parameters(parameters: Parameters) -> Result<(), DeriveError> {
    let minimum = match parameters.algorithm {
        Algorithm::V3 => V3_MIN_LENGTH,
        Algorithm::V2 | Algorithm::LegacyV1 => LEGACY_MIN_LENGTH,
    };
    if !(minimum..=MAX_LENGTH).contains(&parameters.length) {
        return Err(DeriveError::InvalidLength {
            value: parameters.length,
            minimum,
        });
    }
    if parameters.symbols > MAX_SYMBOLS {
        return Err(DeriveError::InvalidSymbols(parameters.symbols));
    }
    if parameters.generation == 0 {
        return Err(DeriveError::InvalidGeneration);
    }
    if matches!(parameters.algorithm, Algorithm::V2 | Algorithm::LegacyV1)
        && !(1..=MAX_SECURITY_BITS).contains(&parameters.security_bits)
    {
        return Err(DeriveError::InvalidSecurityBits(parameters.security_bits));
    }
    Ok(())
}

/// Generate a deterministic password.
///
/// V3 uses canonical Unicode and host handling. The legacy modes intentionally
/// retain the original browser's unusual whitespace and casing behavior.
pub fn generate(
    email: &str,
    passphrase: &str,
    host: &str,
    parameters: Parameters,
) -> Result<String, DeriveError> {
    validate_parameters(parameters)?;

    match parameters.algorithm {
        Algorithm::V3 => {
            let email = canonicalize_v3_email(email)?;
            let host = canonicalize_v3_host(host)?;
            let passphrase = Zeroizing::new(passphrase.nfc().collect::<String>());
            if passphrase.is_empty() {
                return Err(DeriveError::EmptyPassphrase);
            }
            let candidate = derive_v3(&email, passphrase.as_str(), &host, parameters)?;
            Ok(format_v3_password(
                candidate.as_str(),
                parameters.length,
                parameters.symbols,
            ))
        }
        Algorithm::V2 => {
            let email = clean_legacy_field(email).ok_or(DeriveError::EmptyEmail)?;
            let host = clean_legacy_field(host).ok_or(DeriveError::EmptyHost)?;
            let passphrase = Zeroizing::new(clean_v2_passphrase(passphrase));
            if passphrase.is_empty() {
                return Err(DeriveError::EmptyPassphrase);
            }
            let candidate = derive_v2(&email, passphrase.as_str(), &host, parameters)?;
            Ok(format_legacy_password(
                candidate.as_str(),
                parameters.length,
                parameters.symbols,
            ))
        }
        Algorithm::LegacyV1 => {
            let email = clean_legacy_field(email).ok_or(DeriveError::EmptyEmail)?;
            let host = clean_legacy_field(host).ok_or(DeriveError::EmptyHost)?;
            let passphrase = Zeroizing::new(clean_v1_passphrase(passphrase));
            if passphrase.is_empty() {
                return Err(DeriveError::EmptyPassphrase);
            }
            let candidate = derive_v1(&email, passphrase.as_str(), &host, parameters)?;
            Ok(format_legacy_password(
                candidate.as_str(),
                parameters.length,
                parameters.symbols,
            ))
        }
    }
}

fn derive_v3(
    email: &str,
    passphrase: &str,
    host: &str,
    parameters: Parameters,
) -> Result<Zeroizing<String>, DeriveError> {
    let argon_parameters = Argon2Params::new(
        V3_ARGON2_MEMORY_KIB,
        V3_ARGON2_PASSES,
        V3_ARGON2_LANES,
        Some(64),
    )
    .map_err(|_| DeriveError::KdfFailure)?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon_parameters);
    let salt = format!("oracle-v3-argon2id\0{email}\0{host}");
    let mut derived_key = Zeroizing::new([0u8; 64]);
    let mut memory = Zeroizing::new(vec![
        argon2::Block::default();
        V3_ARGON2_MEMORY_KIB as usize
    ]);
    argon2
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt.as_bytes(),
            &mut *derived_key,
            &mut *memory,
        )
        .map_err(|_| DeriveError::KdfFailure)?;

    for counter in 0..u32::MAX {
        let message = pack_v3_message(email, host, parameters.generation, counter);
        let mut mac = HmacSha512::new_from_slice(&*derived_key)
            .expect("HMAC-SHA512 accepts keys of every length");
        mac.update(&message);
        let digest = finalize_digest(mac);
        let encoded = Zeroizing::new(BASE64.encode(digest.as_slice()));
        if is_v3_acceptable(&encoded, parameters.length) {
            return Ok(encoded);
        }
    }

    Err(DeriveError::CounterExhausted)
}

fn derive_v2(
    email: &str,
    passphrase: &str,
    host: &str,
    parameters: Parameters,
) -> Result<Zeroizing<String>, DeriveError> {
    let iterations = 1u32 << parameters.security_bits;
    let mut derived_key = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(
        passphrase.as_bytes(),
        email.as_bytes(),
        iterations,
        &mut *derived_key,
    );

    for counter in 0..u32::MAX {
        let message = pack_v2_message(email, host, parameters.generation, counter);
        let mut mac = HmacSha512::new_from_slice(&*derived_key)
            .expect("HMAC-SHA512 accepts keys of every length");
        mac.update(&message);
        let digest = finalize_digest(mac);
        let encoded = Zeroizing::new(BASE64.encode(digest.as_slice()));
        if is_legacy_acceptable(&encoded) {
            return Ok(encoded);
        }
    }

    Err(DeriveError::CounterExhausted)
}

fn derive_v1(
    email: &str,
    passphrase: &str,
    host: &str,
    parameters: Parameters,
) -> Result<Zeroizing<String>, DeriveError> {
    let divisor = 1u32 << parameters.security_bits;

    for counter in 0..u32::MAX {
        let message = format!(
            "OneShallPass v1.0; {email}; {host}; {}; {counter}",
            parameters.generation
        );
        let mut mac = HmacSha512::new_from_slice(passphrase.as_bytes())
            .expect("HMAC-SHA512 accepts keys of every length");
        mac.update(message.as_bytes());
        let digest = finalize_digest(mac);
        let tail = u32::from_be_bytes(digest[60..64].try_into().expect("four-byte tail"));
        let encoded = Zeroizing::new(BASE64.encode(digest.as_slice()));
        if tail % divisor == 0 && is_legacy_acceptable(&encoded) {
            return Ok(encoded);
        }
    }

    Err(DeriveError::CounterExhausted)
}

fn finalize_digest(mac: HmacSha512) -> Zeroizing<[u8; 64]> {
    let mut output = Zeroizing::new([0u8; 64]);
    let mut digest = mac.finalize().into_bytes();
    output.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    output
}

fn is_v3_acceptable(candidate: &str, length: u8) -> bool {
    let bytes = &candidate.as_bytes()[..length as usize];
    bytes.iter().all(u8::is_ascii_alphanumeric)
        && class_counts(bytes).iter().all(|count| *count > 0)
}

fn is_legacy_acceptable(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    if bytes.len() < MAX_LENGTH as usize
        || !bytes[..MAX_LENGTH as usize]
            .iter()
            .all(u8::is_ascii_alphanumeric)
    {
        return false;
    }

    class_counts(&bytes[..LEGACY_MIN_LENGTH as usize])
        .into_iter()
        .all(|count| (1..=5).contains(&count))
}

fn class_counts(bytes: &[u8]) -> [usize; 3] {
    [
        bytes
            .iter()
            .filter(|byte| byte.is_ascii_uppercase())
            .count(),
        bytes
            .iter()
            .filter(|byte| byte.is_ascii_lowercase())
            .count(),
        bytes.iter().filter(|byte| byte.is_ascii_digit()).count(),
    ]
}

/// V3 chooses symbol positions only from character classes that have a spare
/// member, so symbol insertion can never remove all uppercase, lowercase, or
/// digits from the result.
fn format_v3_password(candidate: &str, length: u8, symbols: u8) -> String {
    let mut output = candidate.as_bytes()[..length as usize].to_vec();
    let mut counts = class_counts(&output);

    for index in 0..symbols as usize {
        let eligible: Vec<usize> = output
            .iter()
            .enumerate()
            .filter_map(|(position, byte)| {
                let class = character_class(*byte)?;
                (counts[class] > 1).then_some(position)
            })
            .collect();
        let position_seed = candidate.as_bytes()[MAX_LENGTH as usize + index];
        let position = eligible[base64_index(position_seed) % eligible.len()];
        let class = character_class(output[position]).expect("eligible characters have a class");
        counts[class] -= 1;

        let symbol_seed = candidate.as_bytes()[MAX_LENGTH as usize + MAX_SYMBOLS as usize + index];
        output[position] = SYMBOL_ALPHABET[base64_index(symbol_seed) % SYMBOL_ALPHABET.len()];
    }

    String::from_utf8(output).expect("password is ASCII")
}

fn character_class(byte: u8) -> Option<usize> {
    if byte.is_ascii_uppercase() {
        Some(0)
    } else if byte.is_ascii_lowercase() {
        Some(1)
    } else if byte.is_ascii_digit() {
        Some(2)
    } else {
        None
    }
}

fn base64_index(byte: u8) -> usize {
    BASE64_ALPHABET
        .iter()
        .position(|value| *value == byte)
        .expect("candidate characters come from the Base64 alphabet")
}

/// Frozen One Shall Pass formatting, including its historical substitution
/// behavior. Do not fix policy quirks here; v1/v2 outputs are compatibility data.
fn format_legacy_password(candidate: &str, length: u8, symbols: u8) -> String {
    let mut output = candidate.as_bytes().to_vec();
    if symbols > 0 {
        let [uppercase, lowercase, digits] = class_counts(&output[..LEGACY_MIN_LENGTH as usize]);

        enum Class {
            Uppercase,
            Lowercase,
            Digit,
        }

        // Upstream tie-breaking is lowercase first, then digits, then uppercase.
        let class = if lowercase >= uppercase && lowercase >= digits {
            Class::Lowercase
        } else if digits > lowercase && digits >= uppercase {
            Class::Digit
        } else {
            Class::Uppercase
        };

        let mut remaining = symbols;
        for byte in output.iter_mut().take(LEGACY_MIN_LENGTH as usize) {
            let matches = match class {
                Class::Uppercase => byte.is_ascii_uppercase(),
                Class::Lowercase => byte.is_ascii_lowercase(),
                Class::Digit => byte.is_ascii_digit(),
            };
            if matches {
                *byte = SYMBOL_ALPHABET[base64_index(*byte) % SYMBOL_ALPHABET.len()];
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
    }

    output.truncate(length as usize);
    String::from_utf8(output).expect("password is ASCII")
}

fn pack_v3_message(email: &str, host: &str, generation: u32, counter: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + email.len() + host.len());
    for field in ["Oracle password v3", email, host] {
        output.extend_from_slice(&(field.len() as u32).to_be_bytes());
        output.extend_from_slice(field.as_bytes());
    }
    output.extend_from_slice(&generation.to_be_bytes());
    output.extend_from_slice(&counter.to_be_bytes());
    output
}

/// Encode v2 exactly as purepack 0.0.x encoded the upstream JavaScript array.
fn pack_v2_message(email: &str, host: &str, generation: u32, counter: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(64 + email.len() + host.len());
    output.push(0x95);
    pack_string(&mut output, "OneShallPass v2.0");
    pack_string(&mut output, email);
    pack_string(&mut output, host);
    pack_positive_integer(&mut output, generation);
    pack_positive_integer(&mut output, counter);
    output
}

fn pack_string(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    match bytes.len() {
        length @ 0..=31 => output.push(0xa0 | length as u8),
        length @ 32..=65_535 => {
            output.push(0xda);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            output.push(0xdb);
            output.extend_from_slice(&(length as u32).to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
}

fn pack_positive_integer(output: &mut Vec<u8>, value: u32) {
    match value {
        0..=0x7f => output.push(value as u8),
        0x80..=0xff => {
            output.push(0xcc);
            output.push(value as u8);
        }
        0x100..=0xffff => {
            output.push(0xcd);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            output.push(0xce);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn clean_v2_passphrase(value: &str) -> String {
    value
        .chars()
        .filter(|character| !is_javascript_whitespace(*character))
        .collect()
}

fn clean_v1_passphrase(value: &str) -> String {
    collapse_javascript_whitespace(value)
}

fn clean_legacy_field(value: &str) -> Option<String> {
    let value = collapse_javascript_whitespace(value).to_lowercase();
    (!value.is_empty()).then_some(value)
}

pub fn canonicalize_v3_email(value: &str) -> Result<String, DeriveError> {
    let normalized = normalize_case(trim_javascript_whitespace(value));
    if normalized.is_empty() {
        return Err(DeriveError::EmptyEmail);
    }
    if normalized
        .chars()
        .any(|character| character.is_control() || is_javascript_whitespace(character))
    {
        return Err(DeriveError::InvalidEmail(
            "whitespace and control characters are not allowed".into(),
        ));
    }
    let (local, domain) = normalized
        .split_once('@')
        .ok_or_else(|| DeriveError::InvalidEmail("expected an address with one `@`".into()))?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(DeriveError::InvalidEmail(
            "expected a non-empty local part and one domain".into(),
        ));
    }
    let domain = canonicalize_domain(domain, false).map_err(DeriveError::InvalidEmail)?;
    Ok(format!("{local}@{domain}"))
}

pub fn canonicalize_v3_host(value: &str) -> Result<String, DeriveError> {
    let normalized = normalize_case(trim_javascript_whitespace(value));
    if normalized.is_empty() {
        return Err(DeriveError::EmptyHost);
    }
    if normalized.contains("://")
        || normalized.contains('/')
        || normalized.contains('?')
        || normalized.contains('#')
        || normalized.contains('@')
    {
        return Err(DeriveError::InvalidHost(
            "pass a hostname only, without a scheme, path, query, fragment, or user info".into(),
        ));
    }
    if normalized
        .chars()
        .any(|character| character.is_control() || is_javascript_whitespace(character))
    {
        return Err(DeriveError::InvalidHost(
            "whitespace and control characters are not allowed".into(),
        ));
    }
    if let Ok(address) = normalized.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    canonicalize_domain(&normalized, true).map_err(DeriveError::InvalidHost)
}

fn canonicalize_domain(value: &str, strip_www: bool) -> Result<String, String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    let value = if strip_www {
        value.strip_prefix("www.").unwrap_or(value)
    } else {
        value
    };
    if value.is_empty() || value.contains(':') {
        return Err("expected a hostname without a port".into());
    }
    let ascii = idna::domain_to_ascii(value).map_err(|_| "domain is not valid IDNA".to_owned())?;
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("domain contains an invalid label".into());
    }
    Ok(ascii)
}

fn normalize_case(value: &str) -> String {
    value
        .nfc()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .nfc()
        .collect()
}

fn trim_javascript_whitespace(value: &str) -> &str {
    value.trim_matches(is_javascript_whitespace)
}

fn collapse_javascript_whitespace(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if is_javascript_whitespace(character) {
            if !result.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                result.push(' ');
                pending_space = false;
            }
            result.push(character);
        }
    }
    result
}

fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_canonicalizes_identity_inputs() {
        assert_eq!(
            canonicalize_v3_email("  Itai@M\u{00fc}nich.example ").unwrap(),
            "itai@xn--mnich-kva.example"
        );
        assert_eq!(
            canonicalize_v3_host("WWW.M\u{00fc}nich.Example.").unwrap(),
            "xn--mnich-kva.example"
        );
        assert!(canonicalize_v3_host("https://example.com/login").is_err());
    }

    #[test]
    fn v3_normalizes_canonically_equivalent_passwords() {
        let parameters = Parameters::default();
        let composed =
            generate("me@example.com", "caf\u{00e9}", "example.com", parameters).unwrap();
        let decomposed = generate(
            "me@example.com",
            "cafe\u{0301}",
            "www.example.com",
            parameters,
        )
        .unwrap();
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn matches_frozen_v3_vectors() {
        let default = generate(
            "alice@example.com",
            "correct horse battery staple",
            "github.com",
            Parameters::default(),
        )
        .unwrap();
        assert_eq!(default, "rESqxYE9e8JSZcBQ");

        let symbols = generate(
            "Alice@Example.COM",
            "correct horse",
            "WWW.Example.COM.",
            Parameters {
                generation: 4,
                symbols: 3,
                ..Parameters::default()
            },
        )
        .unwrap();
        assert_eq!(symbols, "(#cr>b3om4k7V7vj");
    }

    #[test]
    fn v3_symbol_insertion_preserves_every_character_class() {
        let value = format_v3_password(
            "Aa11111111111111BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl",
            16,
            3,
        );
        assert_eq!(
            value
                .chars()
                .filter(|character| SYMBOL_ALPHABET.contains(&(*character as u8)))
                .count(),
            3
        );
        assert!(value.bytes().any(|byte| byte.is_ascii_uppercase()));
        assert!(value.bytes().any(|byte| byte.is_ascii_lowercase()));
        assert!(value.bytes().any(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn messagepack_uses_upstream_encoding() {
        assert_eq!(
            pack_v2_message("a@b.co", "example.com", 1, 0),
            [
                &[0x95, 0xb1][..],
                &b"OneShallPass v2.0"[..],
                &[0xa6][..],
                &b"a@b.co"[..],
                &[0xab][..],
                &b"example.com"[..],
                &[0x01, 0x00][..],
            ]
            .concat()
        );
    }

    #[test]
    fn legacy_policy_rejects_symbols_and_missing_classes() {
        assert!(is_legacy_acceptable("aB3deFGhijklmnop"));
        assert!(!is_legacy_acceptable("abcdefghijklmno1"));
        assert!(!is_legacy_acceptable("aB3de/ghijklmnop"));
    }

    #[test]
    fn legacy_normalization_remains_browser_compatible() {
        assert_eq!(
            clean_legacy_field("  User\t@Example.COM  "),
            Some("user @example.com".into())
        );
        assert_eq!(clean_v2_passphrase(" horse\tbattery\n"), "horsebattery");
        assert_eq!(clean_v1_passphrase(" horse\tbattery\n"), "horse battery");
    }

    #[test]
    fn matches_independent_upstream_v2_vectors() {
        let default = generate(
            "alice@example.com",
            "correct horse battery staple",
            "github.com",
            Parameters::defaults_for(Algorithm::V2),
        )
        .unwrap();
        assert_eq!(default, "a6ZJcRSdLf2s");

        let custom = generate(
            "Alice@Example.COM",
            " correct\thorse ",
            "Example.COM",
            Parameters {
                security_bits: 10,
                generation: 4,
                length: 16,
                symbols: 3,
                algorithm: Algorithm::V2,
            },
        )
        .unwrap();
        assert_eq!(custom, "M`G~@x0UadQFF75a");

        let unicode = generate(
            "\u{00fc}ser@example.com",
            "p\u{00e4}ss phrase",
            "m\u{00fc}nich.example",
            Parameters {
                symbols: 1,
                ..Parameters::defaults_for(Algorithm::V2)
            },
        )
        .unwrap();
        assert_eq!(unicode, "[7xfN5tBFjUK");
    }

    #[test]
    fn matches_independent_upstream_v1_vectors() {
        let default = generate(
            "alice@example.com",
            "correct horse battery staple",
            "github.com",
            Parameters::defaults_for(Algorithm::LegacyV1),
        )
        .unwrap();
        assert_eq!(default, "w9UvlkPNQhfE");

        let custom = generate(
            "Alice@Example.COM organizers",
            " correct\thorse ",
            "Example.COM",
            Parameters {
                security_bits: 8,
                generation: 4,
                length: 16,
                symbols: 2,
                algorithm: Algorithm::LegacyV1,
            },
        )
        .unwrap();
        assert_eq!(custom, "+k6(d9LUUsBYCsGn");
    }
}
