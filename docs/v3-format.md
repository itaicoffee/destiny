# Destiny password format v3

This document freezes v3 so independent implementations can reproduce it.
Every integer is unsigned and big-endian. Every string is UTF-8. Indexes are
zero-based.

## Input normalization

V3 uses Unicode 17 NFC as implemented by `unicode-normalization` 0.1.25.

Email:

1. Remove leading and trailing ECMAScript whitespace.
2. NFC-normalize, lowercase by Unicode scalar, then NFC-normalize again.
3. Require one non-empty local part, one `@`, and a non-empty domain. Reject
   whitespace and controls.
4. Convert the domain through `idna` 1.1.0 to ASCII and require DNS-style labels
   of at most 63 characters, with no leading/trailing hyphen. Total maximum is
   253 characters.

Host:

1. Apply the same trim, NFC, lowercase, and NFC steps.
2. Reject whitespace, controls, schemes, paths, queries, fragments, user info,
   and ports. A raw IP address is canonicalized by the Rust standard library.
3. Remove one final dot and one initial `www.`.
4. Apply the same IDNA and label validation as the email domain.

The master password is NFC-normalized only. Its whitespace and case are exact.

## Key derivation

Use Argon2id version 1.3 (`v=19`) with:

- memory cost: 65,536 KiB
- time cost: 3 passes
- parallelism: 4 lanes
- output: 64 bytes
- password: normalized master-password bytes
- salt: the bytes of `oracle-v3-argon2id`, one NUL byte, normalized email, one
  NUL byte, then normalized host

These values are part of the format and cannot be tuned within v3.
The `oracle-v3-argon2id` identifier is retained from Destiny's former name for
format compatibility; changing it would rotate every existing v3 password.

## Candidate search

For counters from 0 through `2^32 - 2`, construct this message:

```text
u32(len("Oracle password v3")) || "Oracle password v3" ||
u32(len(email))               || email ||
u32(len(host))                || host ||
u32(generation)               || u32(counter)
```

Compute HMAC-SHA-512 using the Argon2 output as the key, then encode the tag
with standard padded Base64. Accept the first candidate whose first `length`
characters are all ASCII alphanumeric and collectively contain at least one
uppercase letter, lowercase letter, and digit. V3 length is 12 through 16 and
generation starts at 1.

The `Oracle password v3` message label is likewise a frozen compatibility
identifier and is not current product branding.

## Symbols

Let the initial output be the accepted candidate's first `length` characters.
Repeat for `i` from zero through `symbols - 1`, where symbols is 0 through 3:

1. Build an ordered list of output positions whose current alphanumeric class
   has more than one remaining member.
2. Convert candidate byte `16 + i` to its index in
   `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=`. Select
   `eligible[index mod eligible.length]` and decrement that class count.
3. Convert candidate byte `19 + i` through the same Base64 index. Replace the
   chosen position with `symbol_alphabet[index mod symbol_alphabet.length]`,
   where the symbol alphabet is:

```text
`~!@#$%^&*()-_+={}[]|;:,<>.?/
```

This guarantees the output retains uppercase, lowercase, and digit classes.

## Test vectors

All unspecified parameters use generation 1, length 16, and zero symbols.

```text
email:    alice@example.com
password: correct horse battery staple
host:     github.com
output:   rESqxYE9e8JSZcBQ

email:      Alice@Example.COM
password:   correct horse
host:       WWW.Example.COM.
generation: 4
symbols:    3
output:     (#cr>b3om4k7V7vj
```
