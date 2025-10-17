using System.Security.Cryptography;

using Blake2s;

using Blake2Sharp;

namespace SecureRemotePassword.Tests; 
/// <summary>
/// Describes the set of test vectors for the Srp validation.
/// </summary>
public class TestVectorSet {
    public string? Comments { get; set; }
    public string? Url { get; set; }
    public required TestVector[] TestVectors { get; set; }

    public class TestVector {
        public required string H { get; set; }
        public int Size { get; set; }
        public required string N { get; set; }
        public required string g { get; set; }
        public required string I { get; set; }
        public required string P { get; set; }
        public required string s { get; set; }
        public required string k { get; set; }
        public required string x { get; set; }
        public required string v { get; set; }
        public required string a { get; set; }
        public required string b { get; set; }
        public required string A { get; set; }
        public required string B { get; set; }
        public required string u { get; set; }
        public required string S { get; set; }

        // optional parameters, missing in RFC5054 test vector
        public string? K { get; set; }
        public string? M1 { get; set; }
        public string? M2 { get; set; }

        /// <summary>
        /// Creates the hasher.
        /// </summary>
        private HashAlgorithm? CreateHasher() {
            HashAlgorithm hasher = SrpHash.CreateHasher(H);
            if (hasher == null) {
                HashAlgorithm blake2s() =>
                    Blake2S.Create().AsHashAlgorithm();

                HashAlgorithm blake2b(int bits) =>
                    new Blake2BHasher(new Blake2BConfig { OutputSizeInBits = bits })
                        .AsHashAlgorithm();

                switch (H.ToLowerInvariant()) {
                    case "blake2s-256":
                        return blake2s();

                    case "blake2b-224":
                        return blake2b(224);

                    case "blake2b-256":
                        return blake2b(256);

                    case "blake2b-384":
                        return blake2b(384);

                    case "blake2b-512":
                        return blake2b(512);
                }
            }

            return hasher;
        }

        /// <summary>
        /// Creates the <see cref="SrpParameters"/> for the current test vector.
        /// </summary>
        public SrpParameters? CreateParameters() {
            // skip test vectors with the unsupported hash format
            HashAlgorithm? hasher = CreateHasher();
            if (hasher == null) {
                return null;
            }

            // convert size in bits to padded length in chars
            int paddedLength = Size / 4;
            return new SrpParameters(CreateHasher!, N, g, paddedLength);
        }
    }
}
