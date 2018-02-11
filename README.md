SHA-2 Algorith (224,256,384,512) 
Implementation of the SHA-2 Algorithm in C#.

Pseudocode for SHA

Padding the message:

private static string paddmessage(string message)
        {
            StringBuilder pad = new StringBuilder();
            StringBuilder length = new StringBuilder();

            foreach (char c in message.ToCharArray())  //Convert the message to binary
            {
                pad.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            int message_length = pad.Length;
            pad.Append(1);
            while ((pad.Length % 512) != 448) //Extend the message so when we add the length we get a multiple of 64 bit
            {
                pad.Append(0);
            }

            length.Append(Convert.ToString(message_length, 2).PadLeft(64, '0')); //Add the length
            pad.Append(length.ToString());
            return pad.ToString();
        }

 private static void chunked(string padded_messgage, out string[] chunks, out int length)
        {
            length = padded_messgage.Length / 512;     //By how many times is the extended message greater than 512 bits
            string[] temp = new string[length];
            for (int i = 0, k = 0; i < padded_messgage.Length; i += 512, k++)
            {
                temp[k] = padded_messgage.Substring(i, 512);  //But 512 bit in one array entery
            }
            chunks = temp;
        }
        
  private static void splitmessage(string message, out uint[] splitted)
        {
            uint[] split = new uint[message.Length / 32];  //Every entery of the array should contain 32 bit
            for (int i = 0, k = 0; i < message.Length; i += 32, k++)
            {
                split[k] = Convert.ToUInt32(message.Substring(i, 32), 2);
            }
            splitted = split;
        }
        
         public static string SHA256(string message)
        {
            uint h0 = 0x6a09e667; //Round constants
            uint h1 = 0xbb67ae85;
            uint h2 = 0x3c6ef372;
            uint h3 = 0xa54ff53a;
            uint h4 = 0x510e527f;
            uint h5 = 0x9b05688c;
            uint h6 = 0x1f83d9ab;
            uint h7 = 0x5be0cd19;

            uint[] k = new uint[] {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

            uint s0, s1, ch, maj, temp1, temp2;

            string padded_message = paddmessage(message);  //Pad the message
            chunked(padded_message, out string[] chunks, out int length); //Put the message into Chunks
            for (int x = 0; x < length; x++)
            {
                uint[] w = new uint[64];
                splitmessage(chunks[x], out uint[] splitted); //Split the message into 32 bit each array entery

                for (int i = 0; i <= 15; i++)
                {
                    w[i] = splitted[i];
                }
// Extend the array to 64 enterys
                for (int i = 16; i < 64; i++)
                {
                    s0 = (w[i - 15] >> 7 | w[i - 15] << (25)) ^ (w[i - 15] >> 18 | w[i - 15] << (14)) ^ (w[i - 15] >> 3);
                    s1 = (w[i - 2] >> 17 | w[i - 2] << (15)) ^ (w[i - 2] >> 19 | w[i - 2] << (13)) ^ (w[i - 2] >> 10);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;
                uint e = h4;
                uint f = h5;
                uint g = h6;
                uint h = h7;
   //Main function     
                for (int i = 0; i < 64; i++)
                {
                    s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
                    ch = (e & f) ^ (~e & g);

                    temp1 = h + s1 + ch + k[i] + w[i];
                    s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
                    maj = (a & b) ^ (a & c) ^ (b & c);
                    temp2 = s0 + maj;
                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }
                h0 += a; //Update Constants
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }
            string H0 = string.Format(h0.ToString("X").PadLeft(8, '0'));
            string H1 = string.Format(h1.ToString("X").PadLeft(8, '0'));
            string H2 = string.Format(h2.ToString("X").PadLeft(8, '0'));
            string H3 = string.Format(h3.ToString("X").PadLeft(8, '0'));
            string H4 = string.Format(h4.ToString("X").PadLeft(8, '0'));
            string H5 = string.Format(h5.ToString("X").PadLeft(8, '0'));
            string H6 = string.Format(h6.ToString("X").PadLeft(8, '0'));
            string H7 = string.Format(h7.ToString("X").PadLeft(8, '0'));
            return H0 + H1 + H2 + H3 + H4 + H5 + H6 + H7; //Output the message in Bigendian
        }
