<?php
require_once __DIR__ . '/vendor/autoload.php';

use XChaChaDemo\XChaCha20;

/**
 * XChaCha20 Stream Demo
 *
 * This script demonstrates:
 * 1. Generating a deterministic stream of pseudorandom bytes using a userland (pure PHP) implementation of XChaCha20.
 * 2. Generating the same stream using PHP's built-in sodium_crypto_stream_xchacha20 function.
 * 3. Encrypting a message using the userland stream and manual XOR operation.
 * 4. Decrypting the ciphertext using sodium_crypto_stream_xchacha20_xor.
 *
 * The goal is to show that the userland implementation is compatible with the built-in function.
 *
 * Requirements: PHP with Libsodium extension enabled.
 */

// Check if Libsodium is available
echo "--- Checking Requirements ---\n";
if (!extension_loaded('sodium')) {
    echo "Libsodium extension not available. Please install/enable it.\n";
    exit(1);
}
echo "Libsodium is enabled.\n\n";

// Setup: Key and Nonce (must be the same for both implementations to generate the same stream)
// The key is the shared secret between sender and receiver
// The nonce (number used once) ensures that even with the same key, we get different keystreams
$key = random_bytes(32);  // 256-bit key (32 bytes)
$nonce = random_bytes(24); // 192-bit nonce (24 bytes) - larger than ChaCha20's 96-bit nonce
echo "Key (hex): " . bin2hex($key) . "\n";
echo "Nonce (hex): " . bin2hex($nonce) . "\n\n";

// Define the length of the stream we want to generate (e.g., 128 bytes for demo)
// In practice, you'd generate exactly the number of bytes needed for your plaintext
$stream_length = 128;
echo "Generating a stream of $stream_length bytes...\n\n";

// --- Step 1: Userland Stream Generation ---
// Create an instance of the userland XChaCha20 class
// The constructor takes the key, nonce, and an optional counter (defaults to 0)
// The counter allows us to start generating keystream from any block position
$userland = new XChaCha20($key, $nonce);

// Generate the stream using the keystream method
// This method generates a deterministic stream of pseudorandom bytes based on the key and nonce
// The same key + nonce combination will always produce the same keystream
$userland_stream = $userland->keystream($stream_length);
echo "Userland Stream (first 32 bytes, hex): " . bin2hex(substr($userland_stream, 0, 32)) . "\n\n";

// --- Step 2: Built-in Stream Generation ---
// Use sodium_crypto_stream_xchacha20 to generate the same stream
// It takes the length, nonce, and key as parameters
// This function is the production-ready implementation from Libsodium
$builtin_stream = sodium_crypto_stream_xchacha20($stream_length, $nonce, $key);
echo "Built-in Stream (first 32 bytes, hex): " . bin2hex(substr($builtin_stream, 0, 32)) . "\n\n";

// Compare the two streams using hash_equals() for timing-safe comparison
// This prevents timing attacks that could reveal information about the comparison
echo "Streams Match: " . (hash_equals($userland_stream, $builtin_stream) ? "✅ YES" : "❌ NO") . "\n";
echo "(If YES, the userland implementation is compatible with the built-in function.)\n\n";

// --- Step 3: Encrypt with Userland Stream + XOR ---
// Define a message to encrypt
$message = "Hello, this is a secret message!";
echo "Message: $message\n";

// Generate a stream of the same length as the message using userland
// Each byte of the message will be XORed with the corresponding byte of the keystream
$userland_stream_for_encrypt = $userland->keystream(strlen($message));

// Encrypt by XORing the message with the stream
// XOR is a bitwise operation that 'flips' bits where the stream is 1
// XOR is its own inverse: A ⊕ B ⊕ B = A, which is why the same operation works for encryption and decryption
$ciphertext = '';
for ($i = 0; $i < strlen($message); $i++) {
    // Convert each character to its ASCII value, XOR with keystream byte, convert back to character
    $ciphertext .= chr(ord($message[$i]) ^ ord($userland_stream_for_encrypt[$i]));
}
echo "Ciphertext (hex): " . bin2hex($ciphertext) . "\n\n";

// --- Step 4: Decrypt with Built-in sodium_crypto_stream_xchacha20_xor ---
// Use the built-in function to decrypt the ciphertext
// It generates the same stream internally and XORs it with the ciphertext
// This demonstrates that our userland implementation is compatible with the production library
$decrypted = sodium_crypto_stream_xchacha20_xor($ciphertext, $nonce, $key);
echo "Decrypted: $decrypted\n";
echo "Decryption Successful: " . ($decrypted === $message ? "✅ YES" : "❌ NO") . "\n\n";

echo "--- Conclusion ---\n";
echo "This demo shows that the userland XChaCha20 implementation generates the exact same pseudorandom stream as the built-in function.\n";
echo "It also demonstrates that data encrypted with the userland stream can be decrypted with the built-in function, proving compatibility.\n";
echo "Note: For production, always use the built-in functions for speed and security.\n"; 