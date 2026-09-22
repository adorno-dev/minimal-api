using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Features.Authorization.Roles.AssignRole;

public static class AssignRoleEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/users/{userId:guid}/roles/{roleName}", Handle)
           .WithTags("Roles")
           .WithSummary("Assign role to user")
           .WithDescription("Assigns an existing Identity role to the specified user.")
           .Produces(StatusCodes.Status204NoContent)
           .Produces(StatusCodes.Status400BadRequest)
           .Produces(StatusCodes.Status404NotFound)
           .Produces(StatusCodes.Status409Conflict)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> Handle(
        Guid userId,
        string roleName,
        [FromServices] UserManager<User> userManager,
        [FromServices] RoleManager<IdentityRole<Guid>> roleManager)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());

        if (user is null)
            return Results.NotFound("User not found.");

        if (!await roleManager.RoleExistsAsync(roleName))
            return Results.NotFound("Role not found.");

        if (await userManager.IsInRoleAsync(user, roleName))
            return Results.Conflict("User already has this role.");

        var result = await userManager.AddToRoleAsync(user, roleName);

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