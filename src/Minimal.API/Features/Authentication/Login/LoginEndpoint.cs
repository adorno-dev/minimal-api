using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.Login;

public static class LoginEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/login", Handle)
        .WithTags("Authentication")
        .WithSummary("Authenticate a user")
        .WithDescription(
            "Validates the user's credentials and returns access and refresh tokens. " +
            "If two-factor authentication is enabled, the response indicates that " +
            "a second authentication factor is required.")
        .Produces<TwoFactorLoginResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> Handle(
        TokenService tokenService,
        LoginRequest request,
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        MinimalDbContext context)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user is null)
            return Results.Unauthorized();

        // DEVELOPMENT ONLY: bypass email confirmation (DELETE BEFORE PRODUCTION)
        user.EmailConfirmed = true;

        var result = await signInManager.CheckPasswordSignInAsync(
            user,
            request.Password,
            lockoutOnFailure: true);

        if (!result.Succeeded)
            return Results.Unauthorized();

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return Results.Ok(
                new TwoFactorLoginResponse(
                    RequiresTwoFactor: true,
                    AccessToken: null,
                    RefreshToken: null));
        }

        var tokens = await tokenService.CreateTokenResponse(
            user,
            context,
            userManager);

        return Results.Ok(
            new TwoFactorLoginResponse(
                RequiresTwoFactor: false,
                AccessToken: tokens.AccessToken,
                RefreshToken: tokens.RefreshToken));
    }
}