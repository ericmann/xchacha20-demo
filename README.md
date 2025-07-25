# XChaCha20 Stream Cipher Implementation

This directory contains an educational implementation of the XChaCha20 stream cipher in pure PHP, designed to demonstrate the inner workings of symmetric cryptography.

## Overview

XChaCha20 is a modern stream cipher that extends ChaCha20 with a larger nonce size (192 bits vs 96 bits) for better flexibility. This implementation is for educational purposes only - for production use, always use established libraries like Libsodium.

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
* Demonstrate how pseudorandom keystreams are generated from a key and nonce.
* Show how XOR operations enable encryption and decryption with the same operation.
* Provide a tangible, albeit non-production-ready, codebase to accompany the PHP[Architect] articles.
* Demonstrate compatibility with production libraries like Libsodium.

### Features Demonstrated

* **Stream Cipher Basics**: How XChaCha20 generates deterministic pseudorandom keystreams.
* **XOR Encryption**: Simple bitwise operations for encryption and decryption.
* **Nonce Management**: The importance of unique nonces for security.
* **Cross-Library Compatibility**: Verification against Libsodium's implementation.
* **Educational Documentation**: Comprehensive comments explaining cryptographic concepts.

### Key Simplifications for Educational Purposes

* **No Authenticated Encryption**: This implementation provides only confidentiality, not authenticity. Real-world applications require AEAD constructions like XChaCha20-Poly1305.
* **Basic Error Handling**: Simplified validation focused on educational clarity rather than production robustness.
* **Educational Comments**: Extensive inline documentation that would be excessive in production code.
* **Deterministic Test Values**: Uses predictable test data for reproducible demonstrations.
* **No Performance Optimizations**: Prioritizes readability over speed.

This project aims to make the _flow_ and _mathematical components_ of XChaCha20 tangible. It is **NOT a secure implementation** and should not be used as a basis for production systems.

Refer to the original PHP[Architect] magazine articles and the "Further Reading" sections within them for more details on secure, production-grade cryptographic protocols and implementations.

