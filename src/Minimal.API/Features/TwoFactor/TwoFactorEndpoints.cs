using Minimal.API.Features.TwoFactor.Disable;
using Minimal.API.Features.TwoFactor.Enable;
using Minimal.API.Features.TwoFactor.Login;
using Minimal.API.Features.TwoFactor.RecoveryCodes;
using Minimal.API.Features.TwoFactor.Setup;

namespace Minimal.API.Features.TwoFactor;

public static class TwoFactorEndpoints
{
    public static IEndpointRouteBuilder MapTwoFactorEndpoints(this IEndpointRouteBuilder app)
    {
        SetupEndpoint.Map(app);
        EnableEndpoint.Map(app);
        LoginEndpoint.Map(app);
        DisableEndpoint.Map(app);
        RecoveryCodesEndpoint.Map(app);

        return app;
    }
}