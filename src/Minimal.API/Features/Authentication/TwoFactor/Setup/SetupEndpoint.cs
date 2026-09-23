using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.TwoFactor.Setup;

public static class SetupEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/2fa/setup", Handle)
           .WithTags("Two-Factor Authentication")
           .WithSummary("Set up authenticator")
           .WithDescription(
               "Generates a new authenticator secret and provisioning URI " +
               "for setting up two-factor authentication.")
           .Produces<SetupResponse>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized)
           .Produces(StatusCodes.Status404NotFound)
           .ProducesProblem(StatusCodes.Status500InternalServerError)
           .RequireAuthorization();
    }

    private static async Task<IResult> Handle(
        ClaimsPrincipal principal,
        UserManager<User> userManager)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
            return Results.Unauthorized();

        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
            return Results.NotFound();

        if (await userManager.GetTwoFactorEnabledAsync(user))
            return Results.BadRequest("Two-factor authentication is already enabled.");

        await userManager.ResetAuthenticatorKeyAsync(user);

        var key = await userManager.GetAuthenticatorKeyAsync(user);

        if (key is null)
            return Results.Problem("Unable to generate authenticator key.");

        var email = await userManager.GetEmailAsync(user);

        var authenticatorUri = AuthenticatorUriGenerator.Generate(email!, key);

        return Results.Ok(new SetupResponse(key, authenticatorUri));
    }
}