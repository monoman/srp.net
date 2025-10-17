namespace SecureRemotePassword;
/// <summary>
/// Ephemeral values used during the SRP-6a authentication.
/// </summary>
public class SrpEphemeral {
    /// <summary>
    /// Gets or sets the public part.
    /// </summary>
    public required string Public { get; set; }

    /// <summary>
    /// Gets or sets the secret part.
    /// </summary>
    public required string Secret { get; set; }
}
