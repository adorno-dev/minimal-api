using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Models;
using Microsoft.EntityFrameworkCore;

namespace Minimal.API.Features.Authentication.DeleteAccount;

public static class DeleteAccountEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapDelete("/auth/account", HandleAsync)
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
    }

    private static async Task<IResult> HandleAsync(
        [FromBody] DeleteAccountRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager,
        MinimalDbContext context)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if (userId is null)
            return Results.Unauthorized();

        var user = await userManager.FindByIdAsync(userId);

        if (user is null)
            return Results.NotFound();

        var passwordValid = await userManager.CheckPasswordAsync(user, request.CurrentPassword);

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
    }
}