namespace Minimal.API.Features.Shared.Contracts;

public sealed record TwoFactorLoginResponse
(
    bool RequiresTwoFactor,
    string? AccessToken,
    string? RefreshToken
);