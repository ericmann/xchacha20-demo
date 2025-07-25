<?php

namespace XChaChaDemo;

/**
 * XChaCha20 Stream Cipher Implementation
 * 
 * This is a pure PHP implementation of the XChaCha20 stream cipher for educational purposes.
 * XChaCha20 extends ChaCha20 with a larger nonce size (192 bits vs 96 bits) for better flexibility.
 * 
 * The algorithm works by:
 * 1. Using HChaCha20 to derive a subkey from the main key and first 16 bytes of nonce
 * 2. Using the subkey with the remaining 8 bytes of nonce in regular ChaCha20
 * 3. Generating a keystream by applying the ChaCha20 block function repeatedly
 * 4. XORing the keystream with plaintext to produce ciphertext
 * 
 * For production use, always use established libraries like Libsodium.
 * 
 * @see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 */
class XChaCha20 {
    /** @var int Key size in bytes (256 bits) */
    private const KEY_SIZE = 32;
    
    /** @var int Nonce size in bytes (192 bits) */
    private const NONCE_SIZE = 24;
    
    /** @var int Block size in bytes (512 bits) */
    private const BLOCK_SIZE = 64;
    
    /** @var int Number of ChaCha20 rounds (20 rounds = 10 double rounds) */
    private const ROUNDS = 20;

    /** @var string The secret key (256 bits) */
    private string $key;
    
    /** @var string The nonce (192 bits) */
    private string $nonce;
    
    /** @var int The block counter (starts at 0) */
    private int $counter;

    /**
     * Constructor for XChaCha20
     * 
     * @param string $key 32-byte secret key
     * @param string $nonce 24-byte nonce (number used once)
     * @param int $counter Starting block counter (default: 0)
     * @throws \InvalidArgumentException If key or nonce size is incorrect
     */
    public function __construct(string $key, string $nonce, int $counter = 0)
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException("Key must be exactly 32 bytes");
        }
        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new \InvalidArgumentException("Nonce must be exactly 24 bytes");
        }
        $this->key = $key;
        $this->nonce = $nonce;
        $this->counter = $counter;
    }

    /**
     * Rotate a 32-bit integer left by the specified number of bits
     * 
     * This is a fundamental operation in ChaCha20. The rotation amount varies
     * between rounds to provide diffusion and prevent patterns.
     * 
     * @param int $v 32-bit value to rotate
     * @param int $c Number of bits to rotate left
     * @return int Rotated 32-bit value
     */
    private function rotl32(int $v, int $c): int {
        // Left shift by c bits, OR with right shift by (32-c) bits
        // The & 0xFFFFFFFF ensures we stay within 32 bits
        return (($v << $c) | ($v >> (32 - $c))) & 0xFFFFFFFF;
    }

    /**
     * ChaCha20 quarter round function
     * 
     * This is the core mixing function of ChaCha20. It operates on 4 state words
     * and applies addition, XOR, and rotation operations. The specific rotation
     * amounts (16, 12, 8, 7) are carefully chosen for optimal diffusion.
     * 
     * @param array $x Reference to the state array (16 32-bit words)
     * @param int $a Index of first word
     * @param int $b Index of second word  
     * @param int $c Index of third word
     * @param int $d Index of fourth word
     */
    private function quarterRound(array &$x, int $a, int $b, int $c, int $d): void {
        // Step 1: a += b; d ^= a; d <<<= 16
        $x[$a] = ($x[$a] + $x[$b]) & 0xFFFFFFFF; 
        $x[$d] ^= $x[$a]; 
        $x[$d] = $this->rotl32($x[$d], 16);
        
        // Step 2: c += d; b ^= c; b <<<= 12
        $x[$c] = ($x[$c] + $x[$d]) & 0xFFFFFFFF; 
        $x[$b] ^= $x[$c]; 
        $x[$b] = $this->rotl32($x[$b], 12);
        
        // Step 3: a += b; d ^= a; d <<<= 8
        $x[$a] = ($x[$a] + $x[$b]) & 0xFFFFFFFF; 
        $x[$d] ^= $x[$a]; 
        $x[$d] = $this->rotl32($x[$d], 8);
        
        // Step 4: c += d; b ^= c; b <<<= 7
        $x[$c] = ($x[$c] + $x[$d]) & 0xFFFFFFFF; 
        $x[$b] ^= $x[$c]; 
        $x[$b] = $this->rotl32($x[$b], 7);
    }

    /**
     * Convert state array to little-endian byte string
     * 
     * @param array $state Array of 32-bit integers
     * @return string Little-endian byte representation
     */
    private function serializeState(array $state): string {
        $out = '';
        foreach ($state as $v) {
            // 'V' format = unsigned long (always 32 bit, little endian byte order)
            $out .= pack('V', $v);
        }
        return $out;
    }

    /**
     * HChaCha20 function for subkey derivation
     * 
     * HChaCha20 is a reduced-round variant of ChaCha20 used in XChaCha20 to derive
     * a subkey from the main key and first 16 bytes of the nonce. This allows
     * XChaCha20 to use a larger nonce while maintaining compatibility with ChaCha20.
     * 
     * The constants are the ASCII representation of "expand 32-byte k":
     * - 0x61707865 = "expa" (little-endian)
     * - 0x3320646e = "nd 3" (little-endian) 
     * - 0x79622d32 = "2-by" (little-endian)
     * - 0x6b206574 = "te k" (little-endian)
     * 
     * @param string $key 32-byte key
     * @param string $nonce16 First 16 bytes of the nonce
     * @return string 32-byte subkey
     */
    private function hchacha20(string $key, string $nonce16): string {
        // ChaCha20 constants: "expand 32-byte k" in little-endian
        $constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        
        // Convert key and nonce to 32-bit words (little-endian)
        $key_words = array_values(unpack('V8', $key));  // 8 words from 32 bytes
        $nonce_words = array_values(unpack('V4', $nonce16)); // 4 words from 16 bytes
        
        // Initialize state matrix (16 words total)
        $state = [
            $constants[0], $constants[1], $constants[2], $constants[3], // Constants
            $key_words[0], $key_words[1], $key_words[2], $key_words[3], // Key (first 4 words)
            $key_words[4], $key_words[5], $key_words[6], $key_words[7], // Key (last 4 words)
            $nonce_words[0], $nonce_words[1], $nonce_words[2], $nonce_words[3] // Nonce
        ];
        
        $working = $state;
        
        // Apply 20 rounds (10 double rounds)
        for ($i = 0; $i < self::ROUNDS; $i += 2) {
            // Column rounds (odd rounds)
            $this->quarterRound($working, 0, 4, 8, 12);
            $this->quarterRound($working, 1, 5, 9, 13);
            $this->quarterRound($working, 2, 6, 10, 14);
            $this->quarterRound($working, 3, 7, 11, 15);
            
            // Diagonal rounds (even rounds)
            $this->quarterRound($working, 0, 5, 10, 15);
            $this->quarterRound($working, 1, 6, 11, 12);
            $this->quarterRound($working, 2, 7, 8, 13);
            $this->quarterRound($working, 3, 4, 9, 14);
        }
        
        // Output: only words 0-3 and 12-15 are used for the subkey
        // This provides the necessary 32 bytes (8 words × 4 bytes each)
        $out = '';
        for ($i = 0; $i < 4; $i++) {
            $out .= pack('V', $working[$i]);
        }
        for ($i = 12; $i < 16; $i++) {
            $out .= pack('V', $working[$i]);
        }
        return $out;
    }

    /**
     * Generate a single ChaCha20 block
     * 
     * This function generates one 64-byte block of keystream using the ChaCha20
     * algorithm. The state is initialized with constants, key, counter, and nonce,
     * then 20 rounds of mixing are applied, and finally the original state is
     * added to the mixed state.
     * 
     * @param string $key 32-byte key
     * @param string $nonce 12-byte nonce (for regular ChaCha20)
     * @param int $counter Block counter
     * @return string 64-byte keystream block
     */
    private function chacha20Block(string $key, string $nonce, int $counter): string {
        // ChaCha20 constants: "expand 32-byte k" in little-endian
        $constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        
        // Convert key and nonce to 32-bit words
        $key_words = array_values(unpack('V8', $key));  // 8 words from 32 bytes
        $nonce_words = array_values(unpack('V3', $nonce)); // 3 words from 12 bytes
        
        // Initialize state matrix (16 words total)
        $state = [
            $constants[0], $constants[1], $constants[2], $constants[3], // Constants
            $key_words[0], $key_words[1], $key_words[2], $key_words[3], // Key (first 4 words)
            $key_words[4], $key_words[5], $key_words[6], $key_words[7], // Key (last 4 words)
            $counter, // Counter (32-bit)
            $nonce_words[0], $nonce_words[1], $nonce_words[2] // Nonce (3 words)
        ];
        
        $working = $state;
        
        // Apply 20 rounds (10 double rounds)
        for ($i = 0; $i < self::ROUNDS; $i += 2) {
            // Column rounds (odd rounds)
            $this->quarterRound($working, 0, 4, 8, 12);
            $this->quarterRound($working, 1, 5, 9, 13);
            $this->quarterRound($working, 2, 6, 10, 14);
            $this->quarterRound($working, 3, 7, 11, 15);
            
            // Diagonal rounds (even rounds)
            $this->quarterRound($working, 0, 5, 10, 15);
            $this->quarterRound($working, 1, 6, 11, 12);
            $this->quarterRound($working, 2, 7, 8, 13);
            $this->quarterRound($working, 3, 4, 9, 14);
        }
        
        // Add the original state to the working state (modular addition)
        for ($i = 0; $i < 16; $i++) {
            $working[$i] = ($working[$i] + $state[$i]) & 0xFFFFFFFF;
        }
        
        return $this->serializeState($working);
    }

    /**
     * Generate XChaCha20 keystream
     * 
     * This is the main function that generates the pseudorandom keystream used
     * for encryption/decryption. It follows the XChaCha20 specification:
     * 
     * 1. Use HChaCha20 to derive a subkey from the main key and first 16 bytes of nonce
     * 2. Use the subkey with the remaining 8 bytes of nonce in regular ChaCha20
     * 3. Generate blocks until we have enough keystream bytes
     * 
     * @param int $length Number of bytes to generate
     * @return string Keystream of specified length
     */
    public function keystream(int $length): string {
        // Step 1: Derive subkey using HChaCha20 with key and first 16 bytes of nonce
        $subkey = $this->hchacha20($this->key, substr($this->nonce, 0, 16));
        
        // Step 2: Use subkey and last 8 bytes of nonce as ChaCha20 nonce
        $nonce = substr($this->nonce, 16, 8);
        
        // For ChaCha20, nonce must be 12 bytes: prepend 4 zero bytes
        $chacha_nonce = "\x00\x00\x00\x00" . $nonce;
        
        $out = '';
        $counter = $this->counter;
        
        // Generate blocks until we have enough keystream bytes
        while (strlen($out) < $length) {
            $block = $this->chacha20Block($subkey, $chacha_nonce, $counter++);
            $out .= $block;
        }
        
        // Return exactly the requested number of bytes
        return substr($out, 0, $length);
    }

    /**
     * Encrypt plaintext using XChaCha20
     * 
     * Encryption is performed by XORing the plaintext with the keystream.
     * Since XOR is its own inverse, the same operation works for decryption.
     * 
     * @param string $plaintext Data to encrypt
     * @return string Ciphertext
     */
    public function encrypt(string $plaintext): string {
        $keystream = $this->keystream(strlen($plaintext));
        return $plaintext ^ $keystream;
    }

    /**
     * Decrypt ciphertext using XChaCha20
     * 
     * Decryption is identical to encryption due to XOR being its own inverse.
     * 
     * @param string $ciphertext Data to decrypt
     * @return string Plaintext
     */
    public function decrypt(string $ciphertext): string {
        return $this->encrypt($ciphertext);
    }
} 