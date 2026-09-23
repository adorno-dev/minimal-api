using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Features.Shared.Extensions;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.TwoFactor.Enable;

public static class EnableEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/2fa/enable", Handle)
           .WithTags("Two-Factor Authentication")
           .WithSummary("Enable two-factor authentication")
           .WithDescription(
               "Enables authenticator-based two-factor authentication after " +
               "validating the supplied authenticator code and returns recovery codes.")
           .Produces<EnableResponse>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized)
           .Produces(StatusCodes.Status404NotFound)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> Handle(
        TwoFactorCodeRequest request,
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

        var valid = await userManager.VerifyTwoFactorTokenAsync(
            user,
            TokenOptions.DefaultAuthenticatorProvider,
            request.Code);

        if (!valid)
            return Results.BadRequest("Invalid authenticator code.");

        var result = await userManager.SetTwoFactorEnabledAsync(user, true);

        if (!result.Succeeded)
            return result.ToValidationProblem();

        var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return Results.Ok(new EnableResponse(recoveryCodes!.ToArray()));
    }
}