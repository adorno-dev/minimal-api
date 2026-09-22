namespace Minimal.API.Features.TwoFactor.Enable;

public sealed record EnableResponse
(
    IEnumerable<string> RecoveryCodes
);