using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.ForgotPassword;

public static class ForgotPasswordEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/forgot-password", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Request password reset")
        .WithDescription("Generates a password reset token and sends it to the user's email address.")
        .Produces(StatusCodes.Status204NoContent);
    }

    private static async Task<IResult> HandleAsync(
        ForgotPasswordRequest request,
        UserManager<User> userManager,
        EmailService emailSender)
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
    }
}