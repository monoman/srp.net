using System.Security;

namespace SecureRemotePassword;
/// <summary>
/// Client-side code of the SRP-6a protocol.
/// </summary>
public class SrpClient : ISrpClient {
    /// <summary>
    /// Initializes a new instance of the <see cref="SrpClient"/> class.
    /// </summary>
    /// <param name="parameters">The parameters of the SRP-6a protocol.</param>
    public SrpClient(SrpParameters parameters = null) {
        Parameters = parameters ?? new SrpParameters();
    }

    /// <summary>
    /// Gets or sets the protocol parameters.
    /// </summary>
    private SrpParameters Parameters { get; set; }

    /// <summary>
    /// Generates the random salt of the same size as a used hash.
    /// </summary>
    /// <param name="saltLength">
    /// An optional, custom salt length specifying the number of bytes. If it is unset,
    /// the `HashSizeBytes` of the hash function from the `Parameters` will be used.
    /// </param>
    public string GenerateSalt(int? saltLength = null) {
        int hashSize = saltLength ?? Parameters.HashSizeBytes;
        return SrpInteger.RandomInteger(hashSize).ToHex();
    }

    /// <summary>
    /// Derives the private key from the given salt, user name and password.
    /// </summary>
    /// <param name="salt">The salt.</param>
    /// <param name="userName">The name of the user.</param>
    /// <param name="password">The password.</param>
    public string DerivePrivateKey(string salt, string userName, string password) {
        // H() — One-way hash function
        SrpParameters.SrpHashFunction H = Parameters.Hash;

        // validate the parameters:
        // s — User's salt, hexadecimal
        // I — login
        // p — Cleartext Password
        SrpInteger s = SrpInteger.FromHex(salt);
        string I = userName + string.Empty;
        string p = password + string.Empty;

        // x = H(s, H(I | ':' | p))  (s is chosen randomly)
        SrpInteger x = H(s, H($"{I}:{p}"));
        return x.ToHex();
    }

    /// <summary>
    /// Derives the verifier from the private key.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    public string DeriveVerifier(string privateKey) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;

        // x — Private key (derived from p and s)
        SrpInteger x = SrpInteger.FromHex(privateKey);

        // v = g^x (computes password verifier)
        SrpInteger v = g.ModPow(x, N);
        return v.ToHex();
    }

    /// <summary>
    /// Generates the ephemeral value.
    /// </summary>
    public SrpEphemeral GenerateEphemeral() {
        // A = g^a (a = random number)
        SrpInteger a = SrpInteger.RandomInteger(Parameters.HashSizeBytes);
        SrpInteger A = ComputeA(a);

        return new SrpEphemeral
        {
            Secret = a.ToHex(),
            Public = A.ToHex(),
        };
    }

    /// <summary>
    /// Computes the public ephemeral value using the specified secret.
    /// </summary>
    /// <param name="a">Secret ephemeral value.</param>
    internal SrpInteger ComputeA(SrpInteger a) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;

        // A = g^a (a = random number)
        return g.ModPow(a, N);
    }

    /// <summary>
    /// Computes the value of u = H(PAD(A), PAD(B)).
    /// </summary>
    /// <param name="A">Client public ehemeral value.</param>
    /// <param name="B">Server public ehemeral value.</param>
    internal SrpInteger ComputeU(SrpInteger A, SrpInteger B) {
        // H — One-way hash function
        // PAD — Pad the number to have the same number of bytes as N
        SrpParameters.SrpHashFunction H = Parameters.Hash;
        System.Func<SrpInteger, SrpInteger> PAD = Parameters.Pad;

        // u = H(PAD(A), PAD(B))
        return H(PAD(A), PAD(B));
    }

    /// <summary>
    /// Computes S, the premaster-secret.
    /// </summary>
    /// <param name="a">Client secret ephemeral value.</param>
    /// <param name="B">Server public ephemeral value.</param>
    /// <param name="u">The computed value of u.</param>
    /// <param name="x">The private key.</param>
    internal SrpInteger ComputeS(SrpInteger a, SrpInteger B, SrpInteger u, SrpInteger x) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        // k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;
        SrpInteger k = Parameters.Multiplier;

        // S = (B - kg^x) ^ (a + ux)
        return (B - (k * g.ModPow(x, N))).ModPow(a + (u * x), N);
    }

    /// <summary>
    /// Derives the client session.
    /// </summary>
    /// <param name="clientSecretEphemeral">The client secret ephemeral.</param>
    /// <param name="serverPublicEphemeral">The server public ephemeral.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="username">The username.</param>
    /// <param name="privateKey">The private key.</param>
    /// <returns>Session key and proof.</returns>
    public SrpSession DeriveSession(string clientSecretEphemeral, string serverPublicEphemeral, string salt, string username, string privateKey) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        // k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        // H — One-way hash function
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;
        SrpParameters.SrpHashFunction H = Parameters.Hash;

        // a — Secret ephemeral value
        // B — Public ephemeral value
        // s — User's salt
        // I — Username
        // x — Private key (derived from p and s)
        SrpInteger a = SrpInteger.FromHex(clientSecretEphemeral);
        SrpInteger B = SrpInteger.FromHex(serverPublicEphemeral);
        SrpInteger s = SrpInteger.FromHex(salt);
        string I = username + string.Empty;
        SrpInteger x = SrpInteger.FromHex(privateKey);

        // A = g^a (a = random number)
        SrpInteger A = g.ModPow(a, N);

        // B % N > 0
        if (B % N == 0) {
            // fixme: .code, .statusCode, etc.
            throw new SecurityException("The server sent an invalid public ephemeral");
        }

        // u = H(PAD(A), PAD(B))
        SrpInteger u = ComputeU(A, B);

        // S = (B - kg^x) ^ (a + ux)
        SrpInteger S = ComputeS(a, B, u, x);

        // K = H(S)
        SrpInteger K = H(S);

        // M1 = H(H(N) xor H(g), H(I), s, A, B, K)
        SrpInteger M1 = H(H(N) ^ H(g), H(I), s, A, B, K);

        return new SrpSession
        {
            Key = K.ToHex(),
            Proof = M1.ToHex(),
        };
    }

    /// <summary>
    /// Verifies the session using the server-provided session proof.
    /// </summary>
    /// <param name="clientPublicEphemeral">The client public ephemeral.</param>
    /// <param name="clientSession">The client session.</param>
    /// <param name="serverSessionProof">The server session proof.</param>
    public void VerifySession(string clientPublicEphemeral, SrpSession clientSession, string serverSessionProof) {
        // H — One-way hash function
        SrpParameters.SrpHashFunction H = Parameters.Hash;

        // A — Public ephemeral values
        // M — Proof of K
        // K — Shared, strong session key
        SrpInteger A = SrpInteger.FromHex(clientPublicEphemeral);
        SrpInteger M = SrpInteger.FromHex(clientSession.Proof);
        SrpInteger K = SrpInteger.FromHex(clientSession.Key);

        // H(A, M, K)
        SrpInteger expected = H(A, M, K);
        SrpInteger actual = SrpInteger.FromHex(serverSessionProof);

        if (actual != expected) {
            // fixme: .code, .statusCode, etc.
            throw new SecurityException("Server provided session proof is invalid");
        }
    }
}
