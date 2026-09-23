using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ResetPassword;

public static class ResetPasswordEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/reset-password", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Reset password")
        .WithDescription(
            "Resets a user's password using a valid password reset token " +
            "and invalidates all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> HandleAsync(
        ResetPasswordRequest request,
        UserManager<User> userManager,
        MinimalDbContext context)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

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
    }
}