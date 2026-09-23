using Minimal.API.Features.Authentication.External.Facebook;
using Minimal.API.Features.Authentication.External.Google;
using Minimal.API.Features.Authentication.External.Microsoft;

namespace Minimal.API.Features.Authentication.External;

public static class ExternalEndpoints
{
    public static IEndpointRouteBuilder Map(this IEndpointRouteBuilder app)
    {
        FacebookStartEndpoint.Map(app);
        FacebookCallbackEndpoint.Map(app);
        GoogleStartEndpoint.Map(app);
        GoogleCallbackEndpoint.Map(app);
        MicrosoftStartEndpoint.Map(app);
        MicrosoftCallbackEndpoint.Map(app);

        return app;
    }
}