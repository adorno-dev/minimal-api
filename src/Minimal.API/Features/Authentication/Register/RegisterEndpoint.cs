using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.Register;

public static class RegisterEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/register", Handle)
        .WithTags("Authentication")
        .WithSummary("Register a new user")
        .WithDescription(
            "Creates a new user account, sends an email confirmation message, " +
            "and returns access and refresh tokens.")
        .Produces<TokenResponse>(StatusCodes.Status201Created)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> Handle(
        IConfiguration configuration,
        TokenService tokenService,
        RegisterRequest request,
        UserManager<User> userManager,
        EmailService emailSender,
        MinimalDbContext context)
    {
        var appBaseUrl = configuration["App:BaseURL"];

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
    }
}