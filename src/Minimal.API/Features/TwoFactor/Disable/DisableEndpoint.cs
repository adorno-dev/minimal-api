using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Features.Shared.Extensions;
using Minimal.API.Models;

namespace Minimal.API.Features.TwoFactor.Disable;

public static class DisableEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/2fa/disable", Handle)
           .WithTags("Two-Factor Authentication")
           .WithSummary("Disable two-factor authentication")
           .WithDescription(
               "Disables authenticator-based two-factor authentication after " +
               "validating the current password and authenticator code.")
           .Produces(StatusCodes.Status204NoContent)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized)
           .Produces(StatusCodes.Status404NotFound)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> Handle(
        DisableRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
            return Results.Unauthorized();

        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
            return Results.NotFound();

        if (!await userManager.GetTwoFactorEnabledAsync(user))
            return Results.BadRequest("Two-factor authentication is not enabled.");

        var passwordValid = await userManager.CheckPasswordAsync(user, request.CurrentPassword);

        if (!passwordValid)
            return Results.Unauthorized();

        var codeValid = await userManager.VerifyTwoFactorTokenAsync(
            user,
            TokenOptions.DefaultAuthenticatorProvider,
            request.Code);

        if (!codeValid)
            return Results.Unauthorized();

        var result = await userManager.SetTwoFactorEnabledAsync(user, false);

        if (!result.Succeeded)
            return result.ToValidationProblem();

        return Results.NoContent();
    }
}