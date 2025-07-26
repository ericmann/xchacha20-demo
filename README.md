# XChaCha20 Stream Cipher and Poly1305 MAC Implementation

This directory contains educational implementations of the XChaCha20 stream cipher and Poly1305 message authentication code in pure PHP, designed to demonstrate the inner workings of symmetric cryptography.

## Overview

**XChaCha20** is a modern stream cipher that extends ChaCha20 with a larger nonce size (192 bits vs 96 bits) for better flexibility.

**Poly1305** is a fast, secure message authentication code that operates on 16-byte blocks and produces a 16-byte tag. It's commonly used with ChaCha20 in the ChaCha20-Poly1305 AEAD construction.

These implementations are for educational purposes only - for production use, always use established libraries like Libsodium.

## Requirements

- PHP 8.3 or higher
- Composer
- Libsodium extension (for the demo script and compatibility tests)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ericmann/xchacha20-demo.git 
   cd xchacha20-demo
   ```

2. **Install dependencies:**
   ```bash
   composer install
   ```

## Usage

### XChaCha20 Basic Usage

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

### Poly1305 Basic Usage

```php
<?php
require_once 'vendor/autoload.php';

use XChaChaDemo\Poly1305;

// Generate a random key
$key = random_bytes(32);   // 256-bit key

// Create Poly1305 instance
$poly1305 = new Poly1305($key);

// Compute MAC for a message
$message = "Hello, world!";
$tag = $poly1305->compute($message);

// Verify the MAC
$is_valid = $poly1305->verify($message, $tag);
echo $is_valid ? "MAC is valid" : "MAC is invalid";
```

### Running the Demos

**XChaCha20 Demo:**
```bash
php xchacha_stream_demo.php
```

**Poly1305 Demo:**
```bash
php poly1305_demo.php
```

The XChaCha20 demo script:
1. Generates a deterministic keystream using the userland implementation
2. Generates the same keystream using Libsodium's `sodium_crypto_stream_xchacha20`
3. Encrypts a message using the userland stream + XOR
4. Decrypts the ciphertext using Libsodium's `sodium_crypto_stream_xchacha20_xor`

The Poly1305 demo script:
1. Demonstrates MAC computation for various message types
2. Shows verification of valid and tampered messages
3. Tests with different keys and binary data

These demonstrate that the userland implementations are compatible with production libraries.

## Testing

### Run Tests

```bash
composer test
```

### Generate Code Coverage (Text)

```bash
composer coverage
```

*Note: Requires Xdebug or pcov to be enabled for coverage reporting.*

### Generate Code Coverage (HTML)

```bash
composer coverage-html
```

Then open `html/index.html` in your browser.

## Disclaimer & Simplifications

This code is an extraction and evolution from a series of articles on cryptography for PHP[Architect] magazine and is intended for **educational purposes only**.

**DO NOT USE THIS CODE IN PRODUCTION. IT IS NOT SECURE.**

### Project Goals

* Illustrate the core concepts of stream cipher operation using XChaCha20 as an example.
* Demonstrate message authentication code operation using Poly1305 as an example.
* Demonstrate how pseudorandom keystreams are generated from a key and nonce.
* Show how XOR operations enable encryption and decryption with the same operation.
* Provide a tangible, albeit non-production-ready, codebase to accompany the PHP[Architect] articles.
* Demonstrate compatibility with production libraries like Libsodium.

### Features Demonstrated

* **Stream Cipher Basics**: How XChaCha20 generates deterministic pseudorandom keystreams.
* **Message Authentication**: How Poly1305 provides authenticity and integrity for messages.
* **XOR Encryption**: Simple bitwise operations for encryption and decryption.
* **Nonce Management**: The importance of unique nonces for security.
* **Cross-Library Compatibility**: Verification against Libsodium's implementation.
* **Educational Documentation**: Comprehensive comments explaining cryptographic concepts.

### Key Simplifications for Educational Purposes

* **No Authenticated Encryption**: The XChaCha20 implementation provides only confidentiality, not authenticity. Real-world applications require AEAD constructions like XChaCha20-Poly1305.
* **Basic Error Handling**: Simplified validation focused on educational clarity rather than production robustness.
* **Educational Comments**: Extensive inline documentation that would be excessive in production code.
* **Deterministic Test Values**: Uses predictable test data for reproducible demonstrations.
* **No Performance Optimizations**: Prioritizes readability over speed.

This project aims to make the _flow_ and _mathematical components_ of XChaCha20 and Poly1305 tangible. It is **NOT a secure implementation** and should not be used as a basis for production systems.

Refer to the original PHP[Architect] magazine articles and the "Further Reading" sections within them for more details on secure, production-grade cryptographic protocols and implementations.

