using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.ResendConfirmation;

public static class ResendConfirmationEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/resend-confirmation", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Resend email confirmation")
        .WithDescription("Generates a new email confirmation token and sends a new confirmation message.")
        .Produces(StatusCodes.Status204NoContent);
    }

    private static async Task<IResult> HandleAsync(
        IConfiguration configuration,
        ResendConfirmationRequest request,
        UserManager<User> userManager,
        EmailService emailSender)
    {
        var appBaseUrl = configuration["App:BaseURL"];

        var user = await userManager.FindByEmailAsync(request.Email);

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
    }
}