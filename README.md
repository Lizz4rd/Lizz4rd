SHA-2 Algorith (224,256,384,512) 
Implementation of the SHA-2 Algorithm in C#.

Pseudocode for SHA (Wikipedia)




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

 Initialize working variables to current hash value:

Compression function main loop:

Add the compressed chunk to the current hash value:

Produce the final hash value (big-endian):
