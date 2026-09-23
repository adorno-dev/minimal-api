using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ChangePassword;

public class ChangePasswordEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/change-password", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Change password")
        .WithDescription(
            "Changes the authenticated user's password and invalidates " +
            "all existing refresh tokens.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        ChangePasswordRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager,
        MinimalDbContext context)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
            return Results.Unauthorized();

        var user = await userManager.FindByIdAsync(userId);

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
    }
}