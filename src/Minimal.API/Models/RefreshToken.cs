namespace Minimal.API.Models;

public sealed class RefreshToken
{
    public Guid Id { get; set; }
    public byte[] TokenHash { get; set; } = [];
    public Guid UserId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public User User { get; set; } = null!;
}