<?php

namespace XChaChaDemo;

/**
 * Poly1305 Message Authentication Code Implementation
 * 
 * This is a pure PHP implementation of the Poly1305 message authentication code for educational purposes.
 * Poly1305 is a fast, secure MAC that operates on 16-byte blocks and produces a 16-byte tag.
 * 
 * The algorithm works by:
 * 1. Converting the key into two 128-bit numbers r and s
 * 2. Processing the message in 16-byte blocks
 * 3. For each block, computing: h = (h + block) * r mod 2^130 - 5
 * 4. Adding s to the final h value and taking modulo 2^128
 * 
 * Poly1305 is commonly used with ChaCha20 in the ChaCha20-Poly1305 AEAD construction.
 * 
 * For production use, always use established libraries like Libsodium.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc8439#section-2.5
 */
class Poly1305 {
    /** @var int Key size in bytes (256 bits) */
    private const KEY_SIZE = 32;
    
    /** @var int Block size in bytes (128 bits) */
    private const BLOCK_SIZE = 16;
    
    /** @var int Tag size in bytes (128 bits) */
    private const TAG_SIZE = 16;
    
    /** @var string The key (256 bits) */
    private string $key;
    
    /** @var string The r value (clamped key bytes 0-15) */
    private string $r;
    
    /** @var string The s value (key bytes 16-31) */
    private string $s;

    /**
     * Constructor for Poly1305
     * 
     * @param string $key 32-byte key
     * @throws \InvalidArgumentException If key size is incorrect
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException("Key must be exactly 32 bytes");
        }
        $this->key = $key;
        $this->initializeKey();
    }

    /**
     * Initialize the r and s values from the key
     * 
     * The key is split into two parts:
     * - r: first 16 bytes, clamped to ensure it's a valid field element
     * - s: last 16 bytes, used as a one-time pad
     */
    private function initializeKey(): void
    {
        // Extract r from first 16 bytes and clamp it
        $r_bytes = substr($this->key, 0, 16);
        $this->r = $this->clampR($r_bytes);
        
        // Extract s from last 16 bytes
        $this->s = substr($this->key, 16, 16);
    }

    /**
     * Clamp the r value to ensure it's a valid field element
     * 
     * @param string $r_bytes The r value as 16 bytes
     * @return string The clamped r value as 16 bytes
     */
    private function clampR(string $r_bytes): string
    {
        // Convert to array of bytes for easier manipulation
        $bytes = array_values(unpack('C*', $r_bytes));
        
        // Clear the top 2 bits of byte 3
        $bytes[3] &= 0x0F;
        
        // Clear the top 2 bits of byte 7
        $bytes[7] &= 0x0F;
        
        // Clear the top 2 bits of byte 11
        $bytes[11] &= 0x0F;
        
        // Clear the top 2 bits of byte 15
        $bytes[15] &= 0x0F;
        
        // Set bit 2 of byte 3
        $bytes[3] |= 0x04;
        
        // Set bit 2 of byte 7
        $bytes[7] |= 0x04;
        
        // Set bit 2 of byte 11
        $bytes[11] |= 0x04;
        
        // Set bit 2 of byte 15
        $bytes[15] |= 0x04;
        
        return pack('C*', ...$bytes);
    }

    /**
     * Convert a 16-byte string to a 130-bit integer
     * 
     * @param string $bytes 16-byte string
     * @return string The integer as a string
     */
    private function bytesToInt130(string $bytes): string
    {
        $result = '0';
        for ($i = 0; $i < 16; $i++) {
            $byte = ord($bytes[$i]);
            $power = bcpow('256', (string)$i);
            $term = bcmul((string)$byte, $power);
            $result = bcadd($result, $term);
        }
        return $result;
    }

    /**
     * Convert a 130-bit integer to a 16-byte string
     * 
     * @param string $int The integer as a string
     * @return string 16-byte string
     */
    private function int130ToBytes(string $int): string
    {
        $bytes = array_fill(0, 16, 0);
        $remaining = $int;
        
        for ($i = 0; $i < 16; $i++) {
            $divisor = bcpow('256', (string)$i);
            if (bccomp($remaining, $divisor) >= 0) {
                $quotient = bcdiv($remaining, $divisor);
                $bytes[$i] = (int)bcmod($quotient, '256');
            }
        }
        
        return pack('C*', ...$bytes);
    }

    /**
     * Add two 130-bit integers
     * 
     * @param string $a First operand
     * @param string $b Second operand
     * @return string Result of addition
     */
    private function add130(string $a, string $b): string
    {
        return bcadd($a, $b);
    }

    /**
     * Multiply two 130-bit integers modulo 2^130 - 5
     * 
     * @param string $a First operand
     * @param string $b Second operand
     * @return string Result of multiplication modulo 2^130 - 5
     */
    private function mulMod130(string $a, string $b): string
    {
        $product = bcmul($a, $b);
        $modulus = bcsub(bcpow('2', '130'), '5');
        return bcmod($product, $modulus);
    }

    /**
     * Process a single 16-byte block
     * 
     * @param string $h Current accumulator value
     * @param string $block 16-byte block to process
     * @return string New accumulator value
     */
    private function processBlock(string $h, string $block): string
    {
        // Convert block to 130-bit integer
        $block_int = $this->bytesToInt130($block);
        
        // Add the block to h
        $h = $this->add130($h, $block_int);
        
        // Multiply by r modulo 2^130 - 5
        $r_int = $this->bytesToInt130($this->r);
        $h = $this->mulMod130($h, $r_int);
        
        return $h;
    }

    /**
     * Compute the Poly1305 MAC for a message
     * 
     * @param string $message The message to authenticate
     * @return string 16-byte MAC tag
     */
    public function compute(string $message): string
    {
        $h = '0';
        $message_length = strlen($message);
        
        // Process complete 16-byte blocks
        $blocks = intdiv($message_length, self::BLOCK_SIZE);
        for ($i = 0; $i < $blocks; $i++) {
            $block = substr($message, $i * self::BLOCK_SIZE, self::BLOCK_SIZE);
            $h = $this->processBlock($h, $block);
        }
        
        // Process the final partial block (if any)
        $remaining = $message_length % self::BLOCK_SIZE;
        if ($remaining > 0) {
            $final_block = substr($message, $blocks * self::BLOCK_SIZE, $remaining);
            // Pad with zeros to 16 bytes
            $final_block = str_pad($final_block, self::BLOCK_SIZE, "\x00");
            // Set the high bit to indicate this is the final block
            $final_block[15] = chr(ord($final_block[15]) | 0x80);
            $h = $this->processBlock($h, $final_block);
        } else {
            // If the message length is a multiple of 16, add a block with just the high bit set
            $final_block = str_repeat("\x00", self::BLOCK_SIZE);
            $final_block[15] = "\x80";
            $h = $this->processBlock($h, $final_block);
        }
        
        // Add s and take modulo 2^128
        $s_int = $this->bytesToInt130($this->s);
        $h = $this->add130($h, $s_int);
        $h = bcmod($h, bcpow('2', '128'));
        
        // Convert to 16-byte tag
        return $this->int130ToBytes($h);
    }

    /**
     * Verify a Poly1305 MAC
     * 
     * @param string $message The original message
     * @param string $tag The MAC tag to verify
     * @return bool True if the tag is valid, false otherwise
     */
    public function verify(string $message, string $tag): bool
    {
        if (strlen($tag) !== self::TAG_SIZE) {
            return false;
        }
        
        $computed_tag = $this->compute($message);
        return hash_equals($computed_tag, $tag);
    }
} 