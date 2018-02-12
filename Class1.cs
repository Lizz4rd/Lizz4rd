using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Security
{
    public class SHA
    {
        public static string SHA224(string message)
        {
            uint h0 = 0x6a09e667;
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

            string padded_message = paddmessage(message);
            chunked(padded_message, out string[] chunks, out int length);
            for (int x = 0; x < length; x++)
            {
                uint[] w = new uint[64];
                splitmessage(chunks[x], out uint[] splitted);

                for (int i = 0; i <= 15; i++)
                {
                    w[i] = splitted[i];
                }

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
                h0 += a;
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
            return H0 + H1 + H2 + H3 + H4 + H5 + H6;
        }
        public static string SHA256(string message)
        {
            uint h0 = 0x6a09e667;
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

            string padded_message = paddmessage(message);
            chunked(padded_message, out string[] chunks, out int length);
            for (int x = 0; x < length; x++)
            {
                uint[] w = new uint[64];
                splitmessage(chunks[x], out uint[] splitted);

                for (int i = 0; i <= 15; i++)
                {
                    w[i] = splitted[i];
                }

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
                h0 += a;
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
            return H0 + H1 + H2 + H3 + H4 + H5 + H6 + H7;
        }
        public static string SHA384(string message)
        {
            ulong h0 = 0xcbbb9d5dc1059ed8;
            ulong h1 = 0x629a292a367cd507;
            ulong h2 = 0x9159015a3070dd17;
            ulong h3 = 0x152fecd8f70e5939;
            ulong h4 = 0x67332667ffc00b31;
            ulong h5 = 0x8eb44a8768581511;
            ulong h6 = 0xdb0c2e0d64f98fa7;
            ulong h7 = 0x47b5481dbefa4fa4;

            ulong[] k = new ulong[] {
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

            ulong s0, s1, ch, maj, temp1, temp2;

            string padded_message = paddmessage512(message);
            chunked512(padded_message, out string[] chunks, out int length);

            for (int x = 0; x < length; x++)
            {
                ulong[] w = new ulong[80];
                splitmessage512(chunks[x], out ulong[] splitted);

                for (int i = 0; i <= 15; i++)
                {
                    w[i] = splitted[i];
                }

                for (int i = 16; i < 80; i++)
                {
                    s0 = (w[i - 15] >> 1 | w[i - 15] << (63)) ^ (w[i - 15] >> 8 | w[i - 15] << (56)) ^ (w[i - 15] >> 7);
                    s1 = (w[i - 2] >> 19 | w[i - 2] << (45)) ^ (w[i - 2] >> 61 | w[i - 2] << (3)) ^ (w[i - 2] >> 6);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                ulong a = h0;
                ulong b = h1;
                ulong c = h2;
                ulong d = h3;
                ulong e = h4;
                ulong f = h5;
                ulong g = h6;
                ulong h = h7;

                for (int i = 0; i < 80; i++)
                {
                    s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23);
                    ch = (e & f) ^ (~e & g);

                    temp1 = h + s1 + ch + k[i] + w[i];
                    s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25);
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
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }
            string H0 = string.Format(h0.ToString("X").PadLeft(16, '0'));
            string H1 = string.Format(h1.ToString("X").PadLeft(16, '0'));
            string H2 = string.Format(h2.ToString("X").PadLeft(16, '0'));
            string H3 = string.Format(h3.ToString("X").PadLeft(16, '0'));
            string H4 = string.Format(h4.ToString("X").PadLeft(16, '0'));
            string H5 = string.Format(h5.ToString("X").PadLeft(16, '0'));
            return H0 + H1 + H2 + H3 + H4 + H5;
        }
        public static string SHA512(string message)
        {
            ulong h0 = 0x6a09e667f3bcc908;
            ulong h1 = 0xbb67ae8584caa73b;
            ulong h2 = 0x3c6ef372fe94f82b;
            ulong h3 = 0xa54ff53a5f1d36f1;
            ulong h4 = 0x510e527fade682d1;
            ulong h5 = 0x9b05688c2b3e6c1f;
            ulong h6 = 0x1f83d9abfb41bd6b;
            ulong h7 = 0x5be0cd19137e2179;

            ulong[] k = new ulong[] {
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
              0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
              0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
              0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
              0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
              0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
              0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
              0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
              0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
              0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
              0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
              0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
              0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
              0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
              0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
              0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

            ulong s0, s1, ch, maj, temp1, temp2;

            string padded_message = paddmessage512(message);
            chunked512(padded_message, out string[] chunks, out int length);

            for (int x = 0; x < length; x++)
            {
                ulong[] w = new ulong[80];
                splitmessage512(chunks[x], out ulong[] splitted);

                for (int i = 0; i <= 15; i++)
                {
                    w[i] = splitted[i];
                }

                for (int i = 16; i < 80; i++)
                {
                    s0 = (w[i - 15] >> 1 | w[i - 15] << (63)) ^ (w[i - 15] >> 8 | w[i - 15] << (56)) ^ (w[i - 15] >> 7);
                    s1 = (w[i - 2] >> 19 | w[i - 2] << (45)) ^ (w[i - 2] >> 61 | w[i - 2] << (3)) ^ (w[i - 2] >> 6);
                    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                }

                ulong a = h0;
                ulong b = h1;
                ulong c = h2;
                ulong d = h3;
                ulong e = h4;
                ulong f = h5;
                ulong g = h6;
                ulong h = h7;

                for (int i = 0; i < 80; i++)
                {
                    s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23);
                    ch = (e & f) ^ (~e & g);

                    temp1 = h + s1 + ch + k[i] + w[i];
                    s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25);
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
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }
            string H0 = string.Format(h0.ToString("X").PadLeft(16, '0'));
            string H1 = string.Format(h1.ToString("X").PadLeft(16, '0'));
            string H2 = string.Format(h2.ToString("X").PadLeft(16, '0'));
            string H3 = string.Format(h3.ToString("X").PadLeft(16, '0'));
            string H4 = string.Format(h4.ToString("X").PadLeft(16, '0'));
            string H5 = string.Format(h5.ToString("X").PadLeft(16, '0'));
            string H6 = string.Format(h6.ToString("X").PadLeft(16, '0'));
            string H7 = string.Format(h7.ToString("X").PadLeft(16, '0'));
            return H0 + H1 + H2 + H3 + H4 + H5 + H6 + H7;
        }

        private static string paddmessage(string message)
        {
            StringBuilder pad = new StringBuilder();
            StringBuilder length = new StringBuilder();

            foreach (char c in message.ToCharArray())
            {
                pad.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            int message_length = pad.Length;
            pad.Append(1);
            while ((pad.Length % 512) != 448)
            {
                pad.Append(0);
            }

            length.Append(Convert.ToString(message_length, 2).PadLeft(64, '0'));
            pad.Append(length.ToString());
            return pad.ToString();
        }
        private static void chunked(string padded_messgage, out string[] chunks, out int length)
        {
            length = padded_messgage.Length / 512;
            string[] temp = new string[length];
            for (int i = 0, k = 0; i < padded_messgage.Length; i += 512, k++)
            {
                temp[k] = padded_messgage.Substring(i, 512);
            }
            chunks = temp;
        }
        private static void splitmessage(string message, out uint[] splitted)
        {
            uint[] split = new uint[message.Length / 32];
            for (int i = 0, k = 0; i < message.Length; i += 32, k++)
            {
                split[k] = Convert.ToUInt32(message.Substring(i, 32), 2);
            }
            splitted = split;
        }

        private static string paddmessage512(string message)
        {
            StringBuilder pad = new StringBuilder();
            StringBuilder length = new StringBuilder();

            foreach (char c in message.ToCharArray())
            {
                pad.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            int message_length = pad.Length;
            pad.Append(1);
            while ((pad.Length % 1024) != 896)
            {
                pad.Append(0);
            }

            length.Append(Convert.ToString(message_length, 2).PadLeft(128, '0'));
            pad.Append(length.ToString());
            return pad.ToString();
        }
        private static void chunked512(string padded_messgage, out string[] chunks, out int length)
        {
            length = padded_messgage.Length / 1024;
            string[] temp = new string[length];
            for (int i = 0, k = 0; i < padded_messgage.Length; i += 1024, k++)
            {
                temp[k] = padded_messgage.Substring(i, 1024);
            }
            chunks = temp;
        }
        private static void splitmessage512(string message, out ulong[] splitted)
        {
            ulong[] split = new ulong[message.Length / 64];
            for (int i = 0, k = 0; i < message.Length; i += 64, k++)
            {
                split[k] = Convert.ToUInt64(message.Substring(i, 64), 2);
            }
            splitted = split;
        }
    }
} 