using System.Security.Claims;

namespace Minimal.API.Endpoints;

public static class DefaultEndpoints
{
    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        app.MapGet("/welcome", async (
            ClaimsPrincipal principal) =>
        {
            var username =
                principal.FindFirstValue(
                    ClaimTypes.Name);

            return Results.Ok(
                $"Welcome, {username}");
        })
        .WithTags("General")
        .WithSummary("Get welcome message")
        .WithDescription("Returns a welcome message containing the authenticated user's username.")
        .Produces<string>(StatusCodes.Status200OK)
        .RequireAuthorization();

        return app;
    }
}