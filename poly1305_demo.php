<?php

require_once 'vendor/autoload.php';

use XChaChaDemo\Poly1305;

echo "Poly1305 Message Authentication Code Demo\n";
echo "========================================\n\n";

// Generate a random 32-byte key
$key = random_bytes(32);
echo "Generated key: " . bin2hex($key) . "\n\n";

// Create Poly1305 instance
$poly1305 = new Poly1305($key);

// Test with different messages
$messages = [
    "Hello, World!",
    "This is a test message for Poly1305 authentication.",
    "", // Empty message
    str_repeat("A", 16), // Exactly 16 bytes
    str_repeat("B", 32), // Exactly 32 bytes
    "Short",
    str_repeat("Long message for testing. ", 10)
];

foreach ($messages as $message) {
    echo "Message: " . (strlen($message) > 50 ? substr($message, 0, 50) . "..." : $message) . "\n";
    echo "Length: " . strlen($message) . " bytes\n";
    
    // Compute MAC
    $tag = $poly1305->compute($message);
    echo "MAC: " . bin2hex($tag) . "\n";
    
    // Verify MAC
    $is_valid = $poly1305->verify($message, $tag);
    echo "Verification: " . ($is_valid ? "PASS" : "FAIL") . "\n";
    
    // Test with tampered message
    $tampered_message = $message . "tampered";
    $is_tampered_valid = $poly1305->verify($tampered_message, $tag);
    echo "Tampered verification: " . ($is_tampered_valid ? "PASS (ERROR!)" : "FAIL (CORRECT)") . "\n";
    
    echo "\n";
}

// Test with binary data
echo "Testing with binary data:\n";
$binary_data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
echo "Binary data: " . bin2hex($binary_data) . "\n";
$binary_tag = $poly1305->compute($binary_data);
echo "MAC: " . bin2hex($binary_tag) . "\n";
$binary_valid = $poly1305->verify($binary_data, $binary_tag);
echo "Verification: " . ($binary_valid ? "PASS" : "FAIL") . "\n\n";

// Test with different keys
echo "Testing with different keys:\n";
$key1 = str_repeat("\x01", 32);
$key2 = str_repeat("\x02", 32);
$poly1305_1 = new Poly1305($key1);
$poly1305_2 = new Poly1305($key2);
$test_message = "Same message, different keys";

$tag1 = $poly1305_1->compute($test_message);
$tag2 = $poly1305_2->compute($test_message);

echo "Key 1 MAC: " . bin2hex($tag1) . "\n";
echo "Key 2 MAC: " . bin2hex($tag2) . "\n";
echo "MACs are different: " . (bin2hex($tag1) !== bin2hex($tag2) ? "YES" : "NO") . "\n\n";

echo "Demo completed successfully!\n"; 