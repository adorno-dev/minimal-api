using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Features.Authorization.Roles.RemoveRole;

public static class RemoveRoleEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapDelete("/auth/users/{userId:guid}/roles/{roleName}", HandleAsync)
           .WithTags("Roles")
           .WithSummary("Remove role from user")
           .WithDescription("Removes an Identity role from the specified user.")
           .Produces(StatusCodes.Status204NoContent)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status404NotFound)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        Guid userId,
        string roleName,
        [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());

        if (user is null)
            return Results.NotFound("User not found.");

        if (!await userManager.IsInRoleAsync(user, roleName))
            return Results.NotFound("User does not have this role.");

        var result = await userManager.RemoveFromRoleAsync(user, roleName);

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