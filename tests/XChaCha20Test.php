<?php

namespace XChaChaDemo\Tests;

use PHPUnit\Framework\TestCase;
use XChaChaDemo\XChaCha20;

class XChaCha20Test extends TestCase
{
    private string $testKey;
    private string $testNonce;

    protected function setUp(): void
    {
        // Use deterministic test values for reproducible tests
        $this->testKey = str_repeat("\x01", 32);  // 32 bytes of 0x01
        $this->testNonce = str_repeat("\x02", 24); // 24 bytes of 0x02
    }

    public function testConstructorWithValidParameters(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $this->assertInstanceOf(XChaCha20::class, $xchacha20);
    }

    public function testConstructorWithInvalidKeySize(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key must be exactly 32 bytes");
        
        new XChaCha20("short_key", $this->testNonce);
    }

    public function testConstructorWithInvalidNonceSize(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Nonce must be exactly 24 bytes");
        
        new XChaCha20($this->testKey, "short_nonce");
    }

    public function testConstructorWithCustomCounter(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce, 5);
        $this->assertInstanceOf(XChaCha20::class, $xchacha20);
    }

    public function testKeystreamGeneration(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $keystream = $xchacha20->keystream(64);
        
        $this->assertEquals(64, strlen($keystream));
        $this->assertIsString($keystream);
    }

    public function testKeystreamDeterministic(): void
    {
        $xchacha20_1 = new XChaCha20($this->testKey, $this->testNonce);
        $xchacha20_2 = new XChaCha20($this->testKey, $this->testNonce);
        
        $keystream1 = $xchacha20_1->keystream(128);
        $keystream2 = $xchacha20_2->keystream(128);
        
        $this->assertEquals($keystream1, $keystream2);
    }

    public function testKeystreamDifferentWithDifferentNonce(): void
    {
        $nonce1 = str_repeat("\x02", 24);
        $nonce2 = str_repeat("\x03", 24);
        
        $xchacha20_1 = new XChaCha20($this->testKey, $nonce1);
        $xchacha20_2 = new XChaCha20($this->testKey, $nonce2);
        
        $keystream1 = $xchacha20_1->keystream(64);
        $keystream2 = $xchacha20_2->keystream(64);
        
        $this->assertNotEquals($keystream1, $keystream2);
    }

    public function testKeystreamDifferentWithDifferentKey(): void
    {
        $key1 = str_repeat("\x01", 32);
        $key2 = str_repeat("\x02", 32);
        
        $xchacha20_1 = new XChaCha20($key1, $this->testNonce);
        $xchacha20_2 = new XChaCha20($key2, $this->testNonce);
        
        $keystream1 = $xchacha20_1->keystream(64);
        $keystream2 = $xchacha20_2->keystream(64);
        
        $this->assertNotEquals($keystream1, $keystream2);
    }

    public function testKeystreamWithCounterOffset(): void
    {
        $xchacha20_1 = new XChaCha20($this->testKey, $this->testNonce, 0);
        $xchacha20_2 = new XChaCha20($this->testKey, $this->testNonce, 1);
        
        $keystream1 = $xchacha20_1->keystream(64);
        $keystream2 = $xchacha20_2->keystream(64);
        
        $this->assertNotEquals($keystream1, $keystream2);
    }

    public function testKeystreamLengthAccuracy(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        
        $lengths = [1, 32, 64, 128, 256, 512];
        
        foreach ($lengths as $length) {
            $keystream = $xchacha20->keystream($length);
            $this->assertEquals($length, strlen($keystream), "Keystream length should be exactly $length bytes");
        }
    }

    public function testEncryptionAndDecryption(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $message = "Hello, XChaCha20!";
        
        $encrypted = $xchacha20->encrypt($message);
        $decrypted = $xchacha20->decrypt($encrypted);
        
        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptionProducesDifferentCiphertext(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $message = "Test message";
        
        $encrypted1 = $xchacha20->encrypt($message);
        $encrypted2 = $xchacha20->encrypt($message);
        
        // With the same key/nonce, we should get the same ciphertext
        $this->assertEquals($encrypted1, $encrypted2);
    }

    public function testEncryptionWithDifferentNonce(): void
    {
        $nonce1 = str_repeat("\x02", 24);
        $nonce2 = str_repeat("\x03", 24);
        $message = "Test message";
        
        $xchacha20_1 = new XChaCha20($this->testKey, $nonce1);
        $xchacha20_2 = new XChaCha20($this->testKey, $nonce2);
        
        $encrypted1 = $xchacha20_1->encrypt($message);
        $encrypted2 = $xchacha20_2->encrypt($message);
        
        $this->assertNotEquals($encrypted1, $encrypted2);
    }

    public function testEncryptionWithEmptyString(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        
        $encrypted = $xchacha20->encrypt("");
        $decrypted = $xchacha20->decrypt($encrypted);
        
        $this->assertEquals("", $decrypted);
    }

    public function testEncryptionWithLongMessage(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $message = str_repeat("A", 1000);
        
        $encrypted = $xchacha20->encrypt($message);
        $decrypted = $xchacha20->decrypt($encrypted);
        
        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptionWithBinaryData(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $message = "\x00\x01\x02\x03\xFF\xFE\xFD\xFC";
        
        $encrypted = $xchacha20->encrypt($message);
        $decrypted = $xchacha20->decrypt($encrypted);
        
        $this->assertEquals($message, $decrypted);
    }

    public function testXorProperty(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        $message = "Test message";
        
        $encrypted = $xchacha20->encrypt($message);
        $encrypted_twice = $xchacha20->encrypt($encrypted);
        
        // XOR is its own inverse: encrypt(encrypt(message)) = message
        $this->assertEquals($message, $encrypted_twice);
    }

    public function testNonceReuseVulnerability(): void
    {
        $nonce = str_repeat("\x02", 24);
        $message1 = "Secret message one";
        $message2 = "Secret message two";
        
        $xchacha20_1 = new XChaCha20($this->testKey, $nonce);
        $xchacha20_2 = new XChaCha20($this->testKey, $nonce);
        
        $encrypted1 = $xchacha20_1->encrypt($message1);
        $encrypted2 = $xchacha20_2->encrypt($message2);
        
        // With nonce reuse, XORing ciphertexts reveals information about plaintexts
        $xor_result = '';
        for ($i = 0; $i < min(strlen($encrypted1), strlen($encrypted2)); $i++) {
            $xor_result .= chr(ord($encrypted1[$i]) ^ ord($encrypted2[$i]));
        }
        
        // The XOR result should not be all zeros (which would indicate identical ciphertexts)
        $this->assertNotEquals(str_repeat("\x00", strlen($xor_result)), $xor_result);
    }

    public function testCompatibilityWithLibsodium(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension not available');
        }
        
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $length = 128;
        
        $xchacha20 = new XChaCha20($key, $nonce);
        $userland_stream = $xchacha20->keystream($length);
        
        $libsodium_stream = sodium_crypto_stream_xchacha20($length, $nonce, $key);
        
        $this->assertEquals($libsodium_stream, $userland_stream);
    }

    public function testCrossCompatibilityEncryption(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension not available');
        }
        
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $message = "Cross-compatibility test message";
        
        // Encrypt with userland implementation
        $xchacha20 = new XChaCha20($key, $nonce);
        $ciphertext = $xchacha20->encrypt($message);
        
        // Decrypt with Libsodium
        $decrypted = sodium_crypto_stream_xchacha20_xor($ciphertext, $nonce, $key);
        
        $this->assertEquals($message, $decrypted);
    }

    public function testCrossCompatibilityDecryption(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension not available');
        }
        
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $message = "Cross-compatibility test message";
        
        // Encrypt with Libsodium
        $ciphertext = sodium_crypto_stream_xchacha20_xor($message, $nonce, $key);
        
        // Decrypt with userland implementation
        $xchacha20 = new XChaCha20($key, $nonce);
        $decrypted = $xchacha20->decrypt($ciphertext);
        
        $this->assertEquals($message, $decrypted);
    }

    public function testKeystreamBlockBoundaries(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        
        // Test keystream generation at block boundaries (64 bytes per block)
        $block_sizes = [63, 64, 65, 127, 128, 129];
        
        foreach ($block_sizes as $size) {
            $keystream = $xchacha20->keystream($size);
            $this->assertEquals($size, strlen($keystream), "Keystream should be exactly $size bytes");
        }
    }

    public function testLargeKeystreamGeneration(): void
    {
        $xchacha20 = new XChaCha20($this->testKey, $this->testNonce);
        
        // Test with a large keystream (multiple blocks)
        $large_keystream = $xchacha20->keystream(1024);
        
        $this->assertEquals(1024, strlen($large_keystream));
        
        // Verify it's not all zeros or all the same value
        $unique_bytes = array_unique(str_split($large_keystream));
        $this->assertGreaterThan(1, count($unique_bytes), "Keystream should have variety");
    }
} 