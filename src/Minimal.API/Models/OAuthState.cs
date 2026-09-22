namespace Minimal.API.Models;

public sealed class OAuthState
{
    public Guid Id { get; set; }
    public string State { get; set; } = string.Empty;
    public string PkceVerifier { get; set; } = string.Empty;
    public string RedirectUrl { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public bool IsUsed { get; set; }
}