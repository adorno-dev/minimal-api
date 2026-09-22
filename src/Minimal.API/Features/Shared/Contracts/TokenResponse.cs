namespace Minimal.API.Features.Shared.Contracts;

public sealed record TokenResponse
(
    string AccessToken,
    string RefreshToken
);