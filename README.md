SHA-2 Algorith (224,256,384,512) 
Implementation of the SHA-2 Algorithm in C#.

Pseudocode for SHA


All variables are 32 bit unsigned integers and addition is calculated modulo 2^32
 For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
 The compression function uses 8 working variables, a through h
 Big-endian convention is used when expressing the constants in this pseudocode,
 and when parsing message block data from bytes to words
 
 Pre-processing:
begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits


Process the message in successive 512-bit chunks:
break message into 512-bit chunks
for each chunk
    create a 64-entry message schedule array w[0..63] of 32-bit words
    (The initial values in w[0..63] don't matter, so many implementations zero them here)
    copy chunk into first 16 words w[0..15] of the message schedule array


Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    for i from 16 to 63
        s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
        s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
        w[i] := w[i-16] + s0 + w[i-7] + s1
