using Minimal.API.Features.Authentication.External;
using Minimal.API.Features.Authentication.Login;
using Minimal.API.Features.Authentication.Register;
using Minimal.API.Features.Authentication.TwoFactor;

namespace Minimal.API.Features.Authentication;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder app)
    {
        LoginEndpoint.Map(app);
        RegisterEndpoint.Map(app);

        ExternalEndpoints.Map(app);
        TwoFactorEndpoints.Map(app);

        return app;
    }
}