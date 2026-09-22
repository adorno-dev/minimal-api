using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Endpoints;

#region +Requests

public sealed record LoginRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Password
);

public sealed record RegisterRequest
(
    [Required]
    [MinLength(3)]
    [MaxLength(30)]
    string Username,

    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Password,

    [Required]
    string ConfirmPassword

) : IValidatableObject
{
    public IEnumerable<ValidationResult>
    Validate(
        ValidationContext validationContext)
    {
        if (Password != ConfirmPassword)
        {
            yield return new ValidationResult(
                new CompareAttribute(
                    nameof(Password))
                    .FormatErrorMessage(
                        nameof(ConfirmPassword)),
                [nameof(ConfirmPassword)]);
        }
    }
}

public sealed record RefreshTokenRequest
(
    [Required]
    string RefreshToken
);

public sealed record ForgotPasswordRequest
(
    [Required]
    [EmailAddress]
    string Email
);

public sealed record ResetPasswordRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Token,

    [Required]
    string NewPassword,

    [Required]
    string ConfirmNewPassword

) : IValidatableObject
{
    public IEnumerable<ValidationResult>
    Validate(
        ValidationContext validationContext)
    {
        if (NewPassword != ConfirmNewPassword)
        {
            yield return new ValidationResult(
                new CompareAttribute(
                    nameof(NewPassword))
                    .FormatErrorMessage(
                        nameof(ConfirmNewPassword)),
                [nameof(ConfirmNewPassword)]);
        }
    }
}

public sealed record ConfirmEmailRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Token
);

public sealed record ResendConfirmationRequest
(
    [Required]
    [EmailAddress]
    string Email
);

public sealed record ChangePasswordRequest
(
    [Required]
    string CurrentPassword,

    [Required]
    string NewPassword,

    [Required]
    string ConfirmNewPassword

) : IValidatableObject
{
    public IEnumerable<ValidationResult>
    Validate(
        ValidationContext validationContext)
    {
        if (NewPassword != ConfirmNewPassword)
        {
            yield return new ValidationResult(
                new CompareAttribute(
                    nameof(NewPassword))
                    .FormatErrorMessage(
                        nameof(ConfirmNewPassword)),
                [nameof(ConfirmNewPassword)]);
        }
    }
}

public sealed record ChangeEmailRequest
(
    [Required]
    [EmailAddress]
    string NewEmail,

    [Required]
    string CurrentPassword
);

public sealed record DeleteAccountRequest
(
    [Required]
    string CurrentPassword
);

public sealed record ChangeUsernameRequest
(
    [Required]
    [MinLength(3)]
    [MaxLength(30)]
    string NewUsername,

    [Required]
    string CurrentPassword
);

public sealed record UpdateProfileRequest
(
    [Phone]
    string? PhoneNumber
);

#endregion

#region +Responses

// public sealed record TokenResponse
// (
//     string AccessToken,
//     string RefreshToken
// );

#endregion

public static class AuthenticationEndpoints
{
    public static WebApplication MapAuthenticationEndpoints(this WebApplication app)
    {
        var appBaseUrl = app.Configuration["App:BaseURL"];

        #region +Development

        if (app.Environment.IsDevelopment())
        {
            app.MapPost("/auth/confirm-email-dev", async (
                string email,
                UserManager<User> userManager) =>
            {
                var user =
                    await userManager.FindByEmailAsync(email);

                if (user is null)
                    return Results.NotFound();

                user.EmailConfirmed = true;

                var result =
                    await userManager.UpdateAsync(user);

                return result.Succeeded
                    ? Results.NoContent()
                    : Results.BadRequest();
            })
            .WithTags("Development")
            .WithSummary("Confirm email for development")
            .WithDescription(
                "Development-only endpoint that manually marks a user's " +
                "email address as confirmed.")
            .Produces(StatusCodes.Status204NoContent)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status404NotFound);
        }

        #endregion

        app.MapPost("/auth/login", async (
            TokenService tokenService,
            LoginRequest request,
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            MinimalDbContext context) =>
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
        })
        .WithTags("Authentication")
        .WithSummary("Authenticate a user")
        .WithDescription(
            "Validates the user's credentials and returns access and refresh tokens. " +
            "If two-factor authentication is enabled, the response indicates that " +
            "a second authentication factor is required.")
        .Produces<TwoFactorLoginResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);

        app.MapPost("/auth/register", async (
            TokenService tokenService,
            RegisterRequest request,
            UserManager<User> userManager,
            EmailService emailSender,
            MinimalDbContext context) =>
        {
            var user = new User
            {
                UserName = request.Username,
                Email = request.Email
            };

            var result = await userManager.CreateAsync(
                user,
                request.Password);

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

            var token =
                await userManager.GenerateEmailConfirmationTokenAsync(user);

            var confirmationUrl =
                $"{appBaseUrl}/auth/confirm-email" +
                $"?userId={Uri.EscapeDataString(user.Id.ToString())}" +
                $"&token={Uri.EscapeDataString(token)}";

            // await emailSender.SendAsync(
            //     user.Email!,
            //     "Confirm your email",
            //     $"<p>Click <a href=\"{confirmationUrl}\">here</a> to confirm your email.</p>");

            return Results.Created(
                $"/users/{user.Id}",
                await tokenService.CreateTokenResponse(
                    user,
                    context,
                    userManager));
        })
        .WithTags("Authentication")
        .WithSummary("Register a new user")
        .WithDescription(
            "Creates a new user account, sends an email confirmation message, " +
            "and returns access and refresh tokens.")
        .Produces<TokenResponse>(StatusCodes.Status201Created)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        app.MapPost("/auth/refresh", async (
            TokenService tokenService,
            [FromBody] RefreshTokenRequest request,
            [FromServices] MinimalDbContext context,
            [FromServices] UserManager<User> userManager) =>
        {
            var response = await tokenService.RotateRefreshToken(
                request.RefreshToken,
                context,
                userManager);

            return response is null
                ? Results.Unauthorized()
                : Results.Ok(response);
        })
        .WithTags("Authentication")
        .WithSummary("Refresh access token")
        .WithDescription(
            "Rotates a valid refresh token and returns a new access token " +
            "and refresh token.")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);

        app.MapPost("/auth/logout", async (
            RefreshTokenRequest request,
            MinimalDbContext context) =>
        {
            var hash = SHA256.HashData(
                Encoding.UTF8.GetBytes(request.RefreshToken));

            await context.RefreshTokens
                .Where(x => x.TokenHash == hash)
                .ExecuteDeleteAsync();

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Log out")
        .WithDescription("Invalidates the supplied refresh token.")
        .Produces(StatusCodes.Status204NoContent);

        app.MapPost("/auth/forgot-password", async (
            ForgotPasswordRequest request,
            UserManager<User> userManager,
            EmailService emailSender) =>
        {
            var user = await userManager.FindByEmailAsync(request.Email);

            if (user is not null)
            {
                var token =
                    await userManager.GeneratePasswordResetTokenAsync(user);

                await emailSender.SendAsync(
                    user.Email!,
                    "Reset your password",
                    $"Your password reset token is: {token}");
            }

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Request password reset")
        .WithDescription("Generates a password reset token and sends it to the user's email address.")
        .Produces(StatusCodes.Status204NoContent);

        app.MapPost("/auth/reset-password", async (
            ResetPasswordRequest request,
            UserManager<User> userManager,
            MinimalDbContext context) =>
        {
            var user =
                await userManager.FindByEmailAsync(request.Email);

            if (user is null)
                return Results.BadRequest();

            var result =
                await userManager.ResetPasswordAsync(
                    user,
                    request.Token,
                    request.NewPassword);

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

            await context.RefreshTokens
                .Where(x => x.UserId == user.Id)
                .ExecuteDeleteAsync();

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Reset password")
        .WithDescription(
            "Resets a user's password using a valid password reset token " +
            "and invalidates all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        app.MapPost("/auth/confirm-email", async (
            ConfirmEmailRequest request,
            UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByEmailAsync(request.Email);

            if (user is null)
                return Results.BadRequest();

            var result =
                await userManager.ConfirmEmailAsync(
                    user,
                    request.Token);

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
        .WithTags("Authentication")
        .WithSummary("Confirm email")
        .WithDescription("Confirms a user's email address using the confirmation token.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        app.MapGet("/auth/confirm-email", async (
            string userId,
            string token,
            UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.BadRequest();

            var result =
                await userManager.ConfirmEmailAsync(
                    user,
                    token);

            return result.Succeeded
                ? Results.NoContent()
                : Results.BadRequest();
        })
        .WithTags("Authentication")
        .WithSummary("Confirm email from link")
        .WithDescription(
            "Confirms a user's email address using the user ID and token " +
            "supplied by the confirmation link.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest);

        app.MapPost("/auth/resend-confirmation", async (
            ResendConfirmationRequest request,
            UserManager<User> userManager,
            EmailService emailSender) =>
        {
            var user =
                await userManager.FindByEmailAsync(request.Email);

            if (user is null ||
                await userManager.IsEmailConfirmedAsync(user))
            {
                return Results.NoContent();
            }

            var token =
                await userManager.GenerateEmailConfirmationTokenAsync(user);

            var confirmationUrl =
                $"{appBaseUrl}/auth/confirm-email" +
                $"?userId={Uri.EscapeDataString(user.Id.ToString())}" +
                $"&token={Uri.EscapeDataString(token)}";

            // await emailSender.SendAsync(
            //     user.Email!,
            //     "Confirm your email",
            //     $"<p>Click <a href=\"{confirmationUrl}\">here</a> to confirm your email.</p>");

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Resend email confirmation")
        .WithDescription("Generates a new email confirmation token and sends a new confirmation message.")
        .Produces(StatusCodes.Status204NoContent);

        app.MapPost("/auth/change-password", async (
            ChangePasswordRequest request,
            ClaimsPrincipal principal,
            UserManager<User> userManager,
            MinimalDbContext context) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.Unauthorized();

            var result =
                await userManager.ChangePasswordAsync(
                    user,
                    request.CurrentPassword,
                    request.NewPassword);

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

            await context.RefreshTokens
                .Where(x => x.UserId == user.Id)
                .ExecuteDeleteAsync();

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Change password")
        .WithDescription(
            "Changes the authenticated user's password and invalidates " +
            "all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .RequireAuthorization();

        app.MapPost("/auth/change-email", async (
            ChangeEmailRequest request,
            ClaimsPrincipal principal,
            UserManager<User> userManager,
            EmailService emailSender) =>
        {
            var userId =
                principal.FindFirstValue(
                    ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.Unauthorized();

            var passwordValid =
                await userManager.CheckPasswordAsync(
                    user,
                    request.CurrentPassword);

            if (!passwordValid)
                return Results.Unauthorized();

            var token =
                await userManager.GenerateChangeEmailTokenAsync(
                    user,
                    request.NewEmail);

            var confirmationUrl =
                $"{appBaseUrl}/account/confirm-email-change" +
                $"?userId={Uri.EscapeDataString(user.Id.ToString())}" +
                $"&email={Uri.EscapeDataString(request.NewEmail)}" +
                $"&token={Uri.EscapeDataString(token)}";

            await emailSender.SendAsync(
                request.NewEmail,
                "Confirm your new email",
                $"<p>Click <a href=\"{confirmationUrl}\">here</a> to confirm your new email.</p>");

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Change email address")
        .WithDescription(
            "Starts the process of changing the authenticated user's email " +
            "address by sending a confirmation link to the new address.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status401Unauthorized)
        .RequireAuthorization();

        app.MapGet("/auth/confirm-email-change", async (
            string userId,
            string email,
            string token,
            UserManager<User> userManager,
            MinimalDbContext context) =>
        {
            var user =
                await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.BadRequest();

            var result =
                await userManager.ChangeEmailAsync(
                    user,
                    email,
                    token);

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

            await context.RefreshTokens
                .Where(x => x.UserId == user.Id)
                .ExecuteDeleteAsync();

            return Results.NoContent();
        })
        .WithTags("Authentication")
        .WithSummary("Confirm email address change")
        .WithDescription(
            "Confirms the requested email address change and invalidates " +
            "all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);

        app.MapDelete("/auth/account", async (
            [FromBody] DeleteAccountRequest request,
            ClaimsPrincipal principal,
            UserManager<User> userManager,
            MinimalDbContext context) =>
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

            var passwordValid =
                await userManager.CheckPasswordAsync(
                    user,
                    request.CurrentPassword);

            if (!passwordValid)
                return Results.Unauthorized();

            await context.RefreshTokens
                .Where(x => x.UserId == user.Id)
                .ExecuteDeleteAsync();

            var result =
                await userManager.DeleteAsync(user);

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
        .WithTags("Authentication")
        .WithSummary("Delete account")
        .WithDescription(
            "Permanently deletes the authenticated user's account and " +
            "invalidates all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();

        app.MapPut("/auth/username", async (
            ChangeUsernameRequest request,
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

            var passwordValid =
                await userManager.CheckPasswordAsync(
                    user,
                    request.CurrentPassword);

            if (!passwordValid)
                return Results.Unauthorized();

            var result =
                await userManager.SetUserNameAsync(
                    user,
                    request.NewUsername);

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
        .WithTags("Authentication")
        .WithSummary("Change username")
        .WithDescription(
            "Changes the authenticated user's username after validating " +
            "the current password.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();

        app.MapPut("/auth/profile", async (
            UpdateProfileRequest request,
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

            var result =
                await userManager.SetPhoneNumberAsync(
                    user,
                    request.PhoneNumber);

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
        .WithTags("Authentication")
        .WithSummary("Update profile")
        .WithDescription("Updates the authenticated user's profile information.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();

        return app;
    }
}