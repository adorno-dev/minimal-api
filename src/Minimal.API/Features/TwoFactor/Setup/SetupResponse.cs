namespace Minimal.API.Features.TwoFactor.Setup;

public sealed record SetupResponse
(
    string SharedKey,
    string AuthenticatorUri
);