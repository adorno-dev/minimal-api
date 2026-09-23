using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ChangeEmail;

public static class ChangeEmailConfirmEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/confirm-email-change", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Confirm email address change")
        .WithDescription(
            "Confirms the requested email address change and invalidates " +
            "all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> HandleAsync(
        string userId,
        string email,
        string token,
        UserManager<User> userManager,
        MinimalDbContext context)
    {
        var user = await userManager.FindByIdAsync(userId);

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
    }
}