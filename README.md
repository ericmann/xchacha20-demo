# XChaCha20 Stream Cipher Implementation

This directory contains an educational implementation of the XChaCha20 stream cipher in pure PHP, designed to demonstrate the inner workings of symmetric cryptography.

## Overview

XChaCha20 is a modern stream cipher that extends ChaCha20 with a larger nonce size (192 bits vs 96 bits) for better flexibility. This implementation is for educational purposes only - for production use, always use established libraries like Libsodium.

## Project Structure

```
symmetric/
├── src/
│   └── XChaCha20.php          # Main XChaCha20 implementation
├── tests/
│   └── XChaCha20Test.php      # Comprehensive unit tests
├── composer.json              # Dependencies and autoloading
├── phpunit.xml.dist          # PHPUnit configuration
├── xchacha_stream_demo.php   # Demonstration script
├── README.md                 # This file
├── LICENSE                   # MIT License
└── .gitignore               # Git ignore rules
```

## Requirements

- PHP 8.3 or higher
- Composer
- Libsodium extension (for the demo script and compatibility tests)

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd symmetric
   ```

2. **Install dependencies:**
   ```bash
   composer install
   ```

## Usage

### Basic Usage

```php
<?php
require_once 'vendor/autoload.php';

use XChaChaDemo\XChaCha20;

// Generate a random key and nonce
$key = random_bytes(32);   // 256-bit key
$nonce = random_bytes(24); // 192-bit nonce

// Create XChaCha20 instance
$xchacha20 = new XChaCha20($key, $nonce);

// Encrypt a message
$message = "Hello, world!";
$ciphertext = $xchacha20->encrypt($message);

// Decrypt the message
$decrypted = $xchacha20->decrypt($ciphertext);
echo $decrypted; // "Hello, world!"
```

### Running the Demo

```bash
php xchacha_stream_demo.php
```

The demo script:
1. Generates a deterministic keystream using the userland implementation
2. Generates the same keystream using Libsodium's `sodium_crypto_stream_xchacha20`
3. Encrypts a message using the userland stream + XOR
4. Decrypts the ciphertext using Libsodium's `sodium_crypto_stream_xchacha20_xor`

This demonstrates that the userland implementation is compatible with the production library.

## Testing

### Run Tests

```bash
composer test
```

### Generate Code Coverage (Text)

```bash
composer coverage
```

*Note: Requires Xdebug to be enabled for coverage reporting.*

### Generate Code Coverage (HTML)

```bash
composer coverage-html
```

Then open `html/index.html` in your browser.

## How XChaCha20 Works

1. **HChaCha20 Subkey Derivation**: Uses the first 16 bytes of the nonce with the key to derive a subkey
2. **ChaCha20 Keystream Generation**: Uses the subkey with the remaining 8 bytes of nonce to generate the keystream
3. **XOR Encryption**: The keystream is XORed with the plaintext to produce ciphertext

The algorithm operates on 32-bit words and uses 20 rounds of mixing operations to generate cryptographically secure pseudorandom bytes.

## Test Coverage

The test suite includes comprehensive tests for:

- **Constructor validation** (key/nonce size validation)
- **Keystream generation** (deterministic behavior, length accuracy)
- **Encryption/decryption** (round-trip functionality)
- **Security properties** (nonce reuse vulnerability demonstration)
- **Cross-compatibility** with Libsodium (when available)
- **Edge cases** (empty strings, binary data, large messages)
- **Block boundaries** (testing at 64-byte block boundaries)

## Security Notes

- **Nonce Reuse**: Never reuse a nonce with the same key - this completely breaks the security
- **Key Management**: Keep keys secure and use cryptographically secure random number generation
- **Production Use**: This implementation is for education only. Use Libsodium or other established libraries for production

## Educational Value

This implementation demonstrates:
- How stream ciphers work at a fundamental level
- The importance of nonces in symmetric cryptography
- How XOR operations enable encryption and decryption
- The structure of modern cryptographic algorithms
- Proper testing practices for cryptographic code

## Development

### Project Structure

The project follows PSR-4 autoloading standards:
- `XChaChaDemo\` namespace maps to `src/` directory
- `XChaChaDemo\Tests\` namespace maps to `tests/` directory

### Adding Tests

To add new tests:
1. Create a new test file in the `tests/` directory
2. Use the `XChaChaDemo\Tests` namespace
3. Extend `PHPUnit\Framework\TestCase`
4. Follow the existing test patterns

### Code Quality

The project includes:
- Comprehensive PHPDoc comments
- PSR-12 coding standards
- Extensive unit test coverage
- Educational inline comments explaining cryptographic concepts

## References

- [XChaCha20 Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- [ChaCha20 and Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- [Libsodium Documentation](https://doc.libsodium.org/)
- [PHPUnit Documentation](https://phpunit.de/) 