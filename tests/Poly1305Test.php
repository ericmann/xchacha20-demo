<?php

namespace XChaChaDemo\Tests;

use PHPUnit\Framework\TestCase;
use XChaChaDemo\Poly1305;

class Poly1305Test extends TestCase
{
    private string $testKey;

    protected function setUp(): void
    {
        // Use deterministic test values for reproducible tests
        $this->testKey = str_repeat("\x01", 32);  // 32 bytes of 0x01
    }

    public function testConstructorWithValidKey(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $this->assertInstanceOf(Poly1305::class, $poly1305);
    }

    public function testConstructorWithInvalidKeySize(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key must be exactly 32 bytes");
        
        new Poly1305("short_key");
    }

    public function testConstructorWithTooLongKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Key must be exactly 32 bytes");
        
        new Poly1305(str_repeat("\x01", 64));
    }

    public function testComputeWithEmptyMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $tag = $poly1305->compute("");
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithShortMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Hello, World!";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithExactBlockSize(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 16);  // Exactly 16 bytes
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithMultipleBlocks(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 64);  // 4 blocks of 16 bytes
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeDeterministic(): void
    {
        $poly1305_1 = new Poly1305($this->testKey);
        $poly1305_2 = new Poly1305($this->testKey);
        $message = "Test message for deterministic computation";
        
        $tag1 = $poly1305_1->compute($message);
        $tag2 = $poly1305_2->compute($message);
        
        $this->assertEquals($tag1, $tag2);
    }

    public function testComputeDifferentWithDifferentKey(): void
    {
        $key1 = str_repeat("\x01", 32);
        $key2 = str_repeat("\x02", 32);
        
        $poly1305_1 = new Poly1305($key1);
        $poly1305_2 = new Poly1305($key2);
        $message = "Test message";
        
        $tag1 = $poly1305_1->compute($message);
        $tag2 = $poly1305_2->compute($message);
        
        $this->assertNotEquals($tag1, $tag2);
    }

    public function testComputeDifferentWithDifferentMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message1 = "First message";
        $message2 = "Second message";
        
        $tag1 = $poly1305->compute($message1);
        $tag2 = $poly1305->compute($message2);
        
        $this->assertNotEquals($tag1, $tag2);
    }

    public function testVerifyWithValidTag(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Message to verify";
        $tag = $poly1305->compute($message);
        
        $this->assertTrue($poly1305->verify($message, $tag));
    }

    public function testVerifyWithInvalidTag(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Message to verify";
        $invalid_tag = str_repeat("\x00", 16);
        
        $this->assertFalse($poly1305->verify($message, $invalid_tag));
    }

    public function testVerifyWithWrongMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message1 = "Original message";
        $message2 = "Modified message";
        $tag = $poly1305->compute($message1);
        
        $this->assertFalse($poly1305->verify($message2, $tag));
    }

    public function testVerifyWithWrongTagSize(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Test message";
        $wrong_size_tag = str_repeat("\x00", 8);  // 8 bytes instead of 16
        
        $this->assertFalse($poly1305->verify($message, $wrong_size_tag));
    }

    public function testVerifyWithEmptyMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $tag = $poly1305->compute("");
        
        $this->assertTrue($poly1305->verify("", $tag));
    }

    public function testComputeWithBinaryData(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithLongMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("This is a long message for testing Poly1305. ", 100);
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithUnicodeMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Hello, 世界! 🌍";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithPartialBlock(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 10);  // 10 bytes (less than 16)
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithOneByteShortOfBlock(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 15);  // 15 bytes (one short of 16)
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithOneByteOverBlock(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 17);  // 17 bytes (one over 16)
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testVerifyWithTamperedMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $original_message = "Original message";
        $tampered_message = "Tampered message";
        $tag = $poly1305->compute($original_message);
        
        $this->assertFalse($poly1305->verify($tampered_message, $tag));
    }

    public function testVerifyWithTamperedTag(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "Test message";
        $original_tag = $poly1305->compute($message);
        
        // Tamper with the tag by flipping one bit
        $tampered_tag = $original_tag;
        $tampered_tag[0] = chr(ord($tampered_tag[0]) ^ 0x01);
        
        $this->assertFalse($poly1305->verify($message, $tampered_tag));
    }

    public function testComputeWithZeroKey(): void
    {
        $zero_key = str_repeat("\x00", 32);
        $poly1305 = new Poly1305($zero_key);
        $message = "Test message";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithAlternatingKey(): void
    {
        $alternating_key = str_repeat("\x00\xFF", 16);  // Alternating 0x00 and 0xFF
        $poly1305 = new Poly1305($alternating_key);
        $message = "Test message";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithMaxKey(): void
    {
        $max_key = str_repeat("\xFF", 32);
        $poly1305 = new Poly1305($max_key);
        $message = "Test message";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithRandomKey(): void
    {
        $random_key = random_bytes(32);
        $poly1305 = new Poly1305($random_key);
        $message = "Test message";
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithRandomMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $random_message = random_bytes(100);
        $tag = $poly1305->compute($random_message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testVerifyWithRandomData(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = random_bytes(50);
        $tag = $poly1305->compute($message);
        
        $this->assertTrue($poly1305->verify($message, $tag));
    }

    public function testComputeWithVeryLongMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("A", 10000);  // 10KB message
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithVeryShortMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "A";  // Single byte
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithSingleByteMessage(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = "\x42";  // Single byte with value 0x42
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithNullBytes(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("\x00", 32);  // 32 null bytes
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }

    public function testComputeWithAllOnes(): void
    {
        $poly1305 = new Poly1305($this->testKey);
        $message = str_repeat("\xFF", 32);  // 32 bytes of 0xFF
        $tag = $poly1305->compute($message);
        
        $this->assertEquals(16, strlen($tag));
        $this->assertIsString($tag);
    }
} 