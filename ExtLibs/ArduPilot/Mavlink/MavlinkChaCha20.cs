using System;

public partial class MAVLink
{
    public static class MavlinkChaCha20
    {
        public static byte[] Key { get; private set; } = new byte[32]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        public static bool EncryptionEnabled { get; set; } = true;

        public static void SetKey(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 32) throw new ArgumentException("ChaCha20 key must be exactly 32 bytes.", nameof(key));
            Key = (byte[])key.Clone();
        }

        public static void GenerateNonce(byte[] nonce, MAVLinkMessage message, bool hasSignature, ulong signatureTimestamp = 0)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (nonce.Length != 12) throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce));
            if (message == null) throw new ArgumentNullException(nameof(message));

            Array.Clear(nonce, 0, 12);

            if (hasSignature)
            {
                byte[] timebytes = BitConverter.GetBytes(signatureTimestamp);
                Array.Copy(timebytes, 0, nonce, 0, 6);
            }
            else
            {
                nonce[0] = message.seq;
            }

            nonce[6] = message.sysid;
            nonce[7] = message.compid;

            uint msgid = message.msgid;
            nonce[8] = (byte)(msgid & 0xFF);
            nonce[9] = (byte)((msgid >> 8) & 0xFF);
            nonce[10] = (byte)((msgid >> 16) & 0xFF);
            // nonce[11] remains 0
        }

        public static void XorBuffer(ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> nonce)
        {
            if (input.Length != output.Length)
                throw new ArgumentException("Input and output must be the same length.");
            if (nonce.Length != 12)
                throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce));
            if (Key == null || Key.Length != 32)
                throw new InvalidOperationException("ChaCha20 key is not initialized or has incorrect length.");

            ChaCha20XOR(Key, 1, nonce, input, output, input.Length);
        }

        public static void XorMessage(MAVLinkMessage message, bool hasSignature = false, ulong signatureTimestamp = 0)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (message.buffer == null) throw new ArgumentNullException("message.buffer");

            int payloadOffset = message.ismavlink2 ? MAVLINK_NUM_HEADER_BYTES : 6;
            int length = message.payloadlength;

            if (length == 0)
                return;
            if (message.buffer.Length < payloadOffset + length)
                throw new ArgumentException("Message buffer too small for payload.", nameof(message));

            byte[] nonce = new byte[12];
            GenerateNonce(nonce, message, hasSignature, signatureTimestamp);

            Span<byte> payload = message.buffer.AsSpan(payloadOffset, length);
            byte[] output = new byte[length];
            XorBuffer(payload, output, nonce);
            output.CopyTo(payload);
        }

        public static void XorMessage(byte[] packet, bool hasSignature = false, ulong signatureTimestamp = 0)
        {
            if (packet == null) throw new ArgumentNullException(nameof(packet));
            if (packet.Length == 0) throw new ArgumentException("Packet cannot be empty.", nameof(packet));

            var message = new MAVLinkMessage(packet, DateTime.UtcNow);
            XorMessage(message, hasSignature, signatureTimestamp);
        }

        private static void u32t8le(uint v, Span<byte> p)
        {
            p[0] = (byte)(v & 0xff);
            p[1] = (byte)((v >> 8) & 0xff);
            p[2] = (byte)((v >> 16) & 0xff);
            p[3] = (byte)((v >> 24) & 0xff);
        }

        private static uint u8t32le(ReadOnlySpan<byte> p)
        {
            uint value = p[3];
            value = (value << 8) | p[2];
            value = (value << 8) | p[1];
            value = (value << 8) | p[0];
            return value;
        }

        private static uint rotl32(uint x, int n)
        {
            return (x << n) | (x >> (-n & 31));
        }

        private static void chacha20_quarterround(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b];
            x[d] = rotl32(x[d] ^ x[a], 16);
            x[c] += x[d];
            x[b] = rotl32(x[b] ^ x[c], 12);
            x[a] += x[b];
            x[d] = rotl32(x[d] ^ x[a], 8);
            x[c] += x[d];
            x[b] = rotl32(x[b] ^ x[c], 7);
        }

        private static void chacha20_serialize(uint[] input, Span<byte> output)
        {
            for (int i = 0; i < 16; i++)
            {
                u32t8le(input[i], output.Slice(i * 4, 4));
            }
        }

        private static void chacha20_block(uint[] input, Span<byte> output, int numRounds)
        {
            uint[] x = new uint[16];
            Array.Copy(input, x, 16);

            for (int i = numRounds; i > 0; i -= 2)
            {
                chacha20_quarterround(x, 0, 4, 8, 12);
                chacha20_quarterround(x, 1, 5, 9, 13);
                chacha20_quarterround(x, 2, 6, 10, 14);
                chacha20_quarterround(x, 3, 7, 11, 15);
                chacha20_quarterround(x, 0, 5, 10, 15);
                chacha20_quarterround(x, 1, 6, 11, 12);
                chacha20_quarterround(x, 2, 7, 8, 13);
                chacha20_quarterround(x, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; i++)
            {
                x[i] += input[i];
            }

            chacha20_serialize(x, output);
        }

        private static void chacha20_init_state(uint[] state, ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce)
        {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            for (int i = 0; i < 8; i++)
            {
                state[4 + i] = u8t32le(key.Slice(i * 4, 4));
            }

            state[12] = counter;

            for (int i = 0; i < 3; i++)
            {
                state[13 + i] = u8t32le(nonce.Slice(i * 4, 4));
            }
        }

        private static void ChaCha20XOR(ReadOnlySpan<byte> key, uint counter, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, int length)
        {
            uint[] state = new uint[16];
            byte[] block = new byte[64];

            chacha20_init_state(state, key, counter, nonce);

            for (int i = 0; i < length; i += 64)
            {
                chacha20_block(state, block, 20);
                state[12]++;

                int chunk = Math.Min(64, length - i);
                for (int j = 0; j < chunk; j++)
                {
                    output[i + j] = (byte)(input[i + j] ^ block[j]);
                }
            }
        }
    }
}
