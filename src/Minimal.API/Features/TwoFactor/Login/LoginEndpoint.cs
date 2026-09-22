using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.TwoFactor.Login;

public static class LoginEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/2fa/login", Handle)
           .WithTags("Two-Factor Authentication")
           .WithSummary("Complete two-factor login")
           .WithDescription(
               "Validates an authenticator code and completes authentication " +
               "by issuing access and refresh tokens.")
           .Produces<TokenResponse>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> Handle(
        TokenService tokenService,
        LoginRequest request,
        UserManager<User> userManager,
        MinimalDbContext context)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user is null)
            return Results.Unauthorized();

        if (!await userManager.GetTwoFactorEnabledAsync(user))
            return Results.BadRequest("Two-factor authentication is not enabled.");

        var valid = await userManager.VerifyTwoFactorTokenAsync(
            user,
            TokenOptions.DefaultAuthenticatorProvider,
            request.Code);

        if (!valid)
            return Results.Unauthorized();

        return Results.Ok(await tokenService.CreateTokenResponse(user, context, userManager));
    }
}