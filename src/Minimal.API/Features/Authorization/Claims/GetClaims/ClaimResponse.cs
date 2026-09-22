namespace Minimal.API.Features.Authorization.Claims.GetClaims;

public sealed record ClaimResponse
(
    string Type,
    string Value
);