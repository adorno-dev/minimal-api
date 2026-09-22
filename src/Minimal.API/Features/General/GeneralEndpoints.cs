using Minimal.API.Features.General.Welcome;

namespace Minimal.API.Features.General;

public static class GeneralEndpoints
{
    public static IEndpointRouteBuilder MapGeneralEndpoints(this IEndpointRouteBuilder app)
    {
        WelcomeEndpoint.Map(app);

        return app;
    }
}