namespace Minimal.API.Features.Authentication.TwoFactor.Enable;

public sealed record EnableResponse
(
    IEnumerable<string> RecoveryCodes
);