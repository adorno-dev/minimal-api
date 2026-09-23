using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.ChangeEmail;

public static class ChangeEmailEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/change-email", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Change email address")
        .WithDescription(
            "Starts the process of changing the authenticated user's email " +
            "address by sending a confirmation link to the new address.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status401Unauthorized)
        .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        IConfiguration configuration,
        ChangeEmailRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager,
        EmailService emailSender)
    {
        var appBaseUrl = configuration["App:BaseURL"];

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

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
    }
}