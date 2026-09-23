using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ConfirmEmail;

public static class ConfirmEmailLinkEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/confirm-email", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Confirm email from link")
        .WithDescription(
            "Confirms a user's email address using the user ID and token " +
            "supplied by the confirmation link.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> HandleAsync(
        string userId,
        string token,
        UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
            return Results.BadRequest();

        var result =
            await userManager.ConfirmEmailAsync(
                user,
                token);

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest();
    }
}