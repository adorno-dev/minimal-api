using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Endpoints;

#region +Requests

public sealed record TwoFactorCodeRequest
(
    [Required]
    string Code
);

public sealed record TwoFactorLoginRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Code
);

public sealed record DisableTwoFactorRequest
(
    [Required]
    string CurrentPassword,

    [Required]
    string Code
);

#endregion

#region +Responses

public sealed record TwoFactorSetupResponse
(
    string SharedKey,
    string AuthenticatorUri
);

public sealed record EnableTwoFactorResponse
(
    IEnumerable<string> RecoveryCodes
);

public sealed record TwoFactorLoginResponse
(
    bool RequiresTwoFactor,
    string? AccessToken,
    string? RefreshToken
);

#endregion

public static class TwoFactorEndpoints
{
    private static string GenerateAuthenticatorUri(string email, string? key)
    {
        var issuer =
            "Minimal.API";

        return "otpauth://totp/" +
            $"{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}" +
            $"?secret={Uri.EscapeDataString(key!)}" +
            $"&issuer={Uri.EscapeDataString(issuer)}" +
            "&digits=6" +
            "&period=30";
    }

    public static WebApplication MapTwoFactorEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/2fa/setup", async (
            ClaimsPrincipal principal,
            UserManager<User> userManager) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.NotFound();

            if (await userManager.GetTwoFactorEnabledAsync(user))
                return Results.BadRequest(
                    "Two-factor authentication is already enabled.");

            await userManager.ResetAuthenticatorKeyAsync(user);

            var key =
                await userManager.GetAuthenticatorKeyAsync(user);

            if (key is null)
                return Results.Problem(
                    "Unable to generate authenticator key.");

            var email =
                await userManager.GetEmailAsync(user);

            var authenticatorUri =
                GenerateAuthenticatorUri(
                    email!,
                    key);

            return Results.Ok(
                new TwoFactorSetupResponse(
                    key,
                    authenticatorUri));
        })
        .WithTags("Two-Factor Authentication")
        .WithSummary("Set up authenticator")
        .WithDescription(
            "Generates a new authenticator secret and provisioning URI " +
            "for setting up two-factor authentication.")
        .Produces<TwoFactorSetupResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status500InternalServerError)
        .RequireAuthorization();

        app.MapPost("/auth/2fa/enable", async (
            TwoFactorCodeRequest request,
            ClaimsPrincipal principal,
            UserManager<User> userManager) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.NotFound();

            if (await userManager.GetTwoFactorEnabledAsync(user))
                return Results.BadRequest(
                    "Two-factor authentication is already enabled.");

            var valid =
                await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    request.Code);

            if (!valid)
                return Results.BadRequest(
                    "Invalid authenticator code.");

            var result =
                await userManager.SetTwoFactorEnabledAsync(
                    user,
                    true);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(
                    result.Errors
                        .GroupBy(error => error.Code)
                        .ToDictionary(
                            group => group.Key,
                            group => group
                                .Select(error => error.Description)
                                .ToArray()));
            }

            var recoveryCodes =
                await userManager.GenerateNewTwoFactorRecoveryCodesAsync(
                    user,
                    10);

            return Results.Ok(
                new EnableTwoFactorResponse(
                    recoveryCodes!.ToArray()));
        })
        .WithTags("Two-Factor Authentication")
        .WithSummary("Enable two-factor authentication")
        .WithDescription(
            "Enables authenticator-based two-factor authentication after " +
            "validating the supplied authenticator code and returns recovery codes.")
        .Produces<EnableTwoFactorResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapPost("/auth/2fa/login", async (
            TokenService tokenService,
            TwoFactorLoginRequest request,
            UserManager<User> userManager,
            MinimalDbContext context) =>
        {
            var user =
                await userManager.FindByEmailAsync(request.Email);

            if (user is null)
                return Results.Unauthorized();

            if (!await userManager.GetTwoFactorEnabledAsync(user))
                return Results.BadRequest(
                    "Two-factor authentication is not enabled.");

            var valid =
                await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    request.Code);

            if (!valid)
                return Results.Unauthorized();

            return Results.Ok(
                await tokenService.CreateTokenResponse(
                    user,
                    context,
                    userManager));
        })
        .WithTags("Two-Factor Authentication")
        .WithSummary("Complete two-factor login")
        .WithDescription(
            "Validates an authenticator code and completes authentication " +
            "by issuing access and refresh tokens.")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized);

        app.MapPost("/auth/2fa/disable", async (
            DisableTwoFactorRequest request,
            ClaimsPrincipal principal,
            UserManager<User> userManager) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.NotFound();

            if (!await userManager.GetTwoFactorEnabledAsync(user))
                return Results.BadRequest(
                    "Two-factor authentication is not enabled.");

            var passwordValid =
                await userManager.CheckPasswordAsync(
                    user,
                    request.CurrentPassword);

            if (!passwordValid)
                return Results.Unauthorized();

            var codeValid =
                await userManager.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    request.Code);

            if (!codeValid)
                return Results.Unauthorized();

            var result =
                await userManager.SetTwoFactorEnabledAsync(
                    user,
                    false);

            if (!result.Succeeded)
            {
                return Results.ValidationProblem(
                    result.Errors
                        .GroupBy(error => error.Code)
                        .ToDictionary(
                            group => group.Key,
                            group => group
                                .Select(error => error.Description)
                                .ToArray()));
            }

            return Results.NoContent();
        })
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

        app.MapPost("/auth/2fa/recovery-codes", async (
            ClaimsPrincipal principal,
            UserManager<User> userManager) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.NotFound();

            var isEnabled =
                await userManager.GetTwoFactorEnabledAsync(user);

            if (!isEnabled)
                return Results.BadRequest(
                    "Two-factor authentication is not enabled.");

            var recoveryCodes =
                await userManager.GenerateNewTwoFactorRecoveryCodesAsync(
                    user,
                    10);

            return Results.Ok(recoveryCodes);
        })
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

        return app;
    }
}