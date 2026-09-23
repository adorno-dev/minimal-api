using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ChangeUsername;

public static class ChangeUsernameEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPut("/auth/username", HandleAsync)
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
    }

    private static async Task<IResult> HandleAsync(
        ChangeUsernameRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager)
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
    }
}