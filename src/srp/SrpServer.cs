namespace SecureRemotePassword;
/// <summary>
/// Server-side code of the SRP-6a protocol.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SrpServer"/> class.
/// </remarks>
/// <param name="parameters">The parameters of the SRP-6a protocol.</param>
public class SrpServer(SrpParameters? parameters = null) : ISrpServer {

    /// <summary>
    /// Gets or sets the protocol parameters.
    /// </summary>
    internal SrpParameters Parameters { get; set; } = parameters ?? new SrpParameters();

    /// <summary>
    /// Generates the ephemeral value from the given verifier.
    /// </summary>
    /// <param name="verifier">Verifier.</param>
    public SrpEphemeral GenerateEphemeral(string verifier) {
        // B = kv + g^b (b = random number)
        SrpInteger b = SrpInteger.RandomInteger(Parameters.HashSizeBytes);
        SrpInteger B = ComputeB(SrpInteger.FromHex(verifier), b);

        return new SrpEphemeral
        {
            Secret = b.ToHex(),
            Public = B.ToHex(),
        };
    }

    /// <summary>
    /// Generates the public ephemeral value from the given verifier and the secret.
    /// </summary>
    /// <param name="v">Password verifier.</param>
    /// <param name="b">Secret server ephemeral.</param>
    internal SrpInteger ComputeB(SrpInteger v, SrpInteger b) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        // k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;
        SrpInteger k = Parameters.Multiplier;

        // B = kv + g^b (b = random number)
        return ((k * v) + g.ModPow(b, N)) % N;
    }

    /// <summary>
    /// Computes S, the premaster-secret.
    /// </summary>
    /// <param name="A">Client public ephemeral value.</param>
    /// <param name="b">Server secret ephemeral value.</param>
    /// <param name="u">The computed value of u.</param>
    /// <param name="v">The verifier.</param>
    internal SrpInteger ComputeS(SrpInteger A, SrpInteger b, SrpInteger u, SrpInteger v) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        SrpInteger N = Parameters.Prime;

        // S = (Av^u) ^ b (computes session key)
        return (A * v.ModPow(u, N)).ModPow(b, N);
    }

    /// <summary>
    /// Derives the server session.
    /// </summary>
    /// <param name="serverSecretEphemeral">The server secret ephemeral.</param>
    /// <param name="clientPublicEphemeral">The client public ephemeral.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="username">The username.</param>
    /// <param name="verifier">The verifier.</param>
    /// <param name="clientSessionProof">The client session proof value.</param>
    /// <returns>Session key and proof.</returns>
    public SrpSession DeriveSession(string serverSecretEphemeral, string clientPublicEphemeral, string salt, string username, string verifier, string clientSessionProof) {
        // N — A large safe prime (N = 2q+1, where q is prime)
        // g — A generator modulo N
        // k — Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        // H — One-way hash function
        // PAD — Pad the number to have the same number of bytes as N
        SrpInteger N = Parameters.Prime;
        SrpInteger g = Parameters.Generator;
        SrpInteger k = Parameters.Multiplier;
        SrpParameters.SrpHashFunction H = Parameters.Hash;
        System.Func<SrpInteger, SrpInteger> PAD = Parameters.Pad;

        // b — Secret ephemeral values
        // A — Public ephemeral values
        // s — User's salt
        // p — Cleartext Password
        // I — Username
        // v — Password verifier
        SrpInteger b = SrpInteger.FromHex(serverSecretEphemeral);
        SrpInteger A = SrpInteger.FromHex(clientPublicEphemeral);
        SrpInteger s = SrpInteger.FromHex(salt);
        string I = username + string.Empty;
        SrpInteger v = SrpInteger.FromHex(verifier);

        // B = kv + g^b (b = random number)
        SrpInteger B = ComputeB(v, b);

        // A % N > 0
        if (A % N == 0) {
            // fixme: .code, .statusCode, etc.
            throw new SecurityException("The client sent an invalid public ephemeral");
        }

        // u = H(PAD(A), PAD(B))
        SrpInteger u = H(PAD(A), PAD(B));

        // S = (Av^u) ^ b (computes session key)
        SrpInteger S = ComputeS(A, b, u, v);

        // K = H(S)
        SrpInteger K = H(S);

        // M = H(H(N) xor H(g), H(I), s, A, B, K)
        SrpInteger M = H(H(N) ^ H(g), H(I), s, A, B, K);

        // validate client session proof
        SrpInteger expected = M;
        SrpInteger actual = SrpInteger.FromHex(clientSessionProof);
        if (actual != expected) {
            // fixme: .code, .statusCode, etc.
            throw new SecurityException("Client provided session proof is invalid");
        }

        // P = H(A, M, K)
        SrpInteger P = H(A, M, K);

        return new SrpSession
        {
            Key = K.ToHex(),
            Proof = P.ToHex(),
        };
    }
}
