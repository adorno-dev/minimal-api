using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ConfirmEmail;

public static class ConfirmEmailDevelopmentEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/confirm-email-dev", HandleAsync)
        .WithTags("Development")
        .WithSummary("Confirm email for development")
        .WithDescription(
            "Development-only endpoint that manually marks a user's " +
            "email address as confirmed.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> HandleAsync(
        string email,
        UserManager<User> userManager)
    {
        var user = await userManager.FindByEmailAsync(email);

        if (user is null)
            return Results.NotFound();

        user.EmailConfirmed = true;

        var result =
            await userManager.UpdateAsync(user);

        return result.Succeeded
            ? Results.NoContent()
            : Results.BadRequest();
    }
}