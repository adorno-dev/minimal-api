using System.Security.Claims;

namespace Minimal.API.Features.General.Welcome;

public static class WelcomeEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/welcome", Handle)
           .WithTags("General")
           .WithSummary("Get welcome message")
           .WithDescription("Returns a welcome message containing the authenticated user's username.")
           .Produces<string>(StatusCodes.Status200OK)
           .RequireAuthorization();
    }

    private static IResult Handle(ClaimsPrincipal principal)
    {
        var username = principal.FindFirstValue(ClaimTypes.Name);

        return Results.Ok($"Welcome, {username}");
    }
}