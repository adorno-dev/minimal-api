using Minimal.API.Features.Authentication.TwoFactor.Disable;
using Minimal.API.Features.Authentication.TwoFactor.Enable;
using Minimal.API.Features.Authentication.TwoFactor.Login;
using Minimal.API.Features.Authentication.TwoFactor.RecoveryCodes;
using Minimal.API.Features.Authentication.TwoFactor.Setup;

namespace Minimal.API.Features.Authentication.TwoFactor;

public static class TwoFactorEndpoints
{
    public static IEndpointRouteBuilder Map(this IEndpointRouteBuilder app)
    {
        SetupEndpoint.Map(app);
        EnableEndpoint.Map(app);
        LoginEndpoint.Map(app);
        DisableEndpoint.Map(app);
        RecoveryCodesEndpoint.Map(app);

        return app;
    }
}