namespace Minimal.API.Features.Authentication.TwoFactor.Setup;

public sealed record SetupResponse
(
    string SharedKey,
    string AuthenticatorUri
);