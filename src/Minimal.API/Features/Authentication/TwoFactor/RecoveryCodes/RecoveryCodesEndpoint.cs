using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.TwoFactor.RecoveryCodes;

public static class RecoveryCodesEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/2fa/recovery-codes", Handle)
           .WithTags("Two-Factor Authentication")
           .WithSummary("Generate recovery codes")
           .WithDescription(
               "Generates a new set of recovery codes for the authenticated " +
               "user's two-factor authentication.")
           .Produces<IEnumerable<string>>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized)
           .Produces(StatusCodes.Status404NotFound)
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

        var isEnabled = await userManager.GetTwoFactorEnabledAsync(user);

        if (!isEnabled)
            return Results.BadRequest("Two-factor authentication is not enabled.");

        var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return Results.Ok(recoveryCodes);
    }
}