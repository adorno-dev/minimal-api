using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Endpoints;

#region +Requests

public sealed record CreateRoleRequest
(
    [Required]
    [MinLength(1)]
    [MaxLength(50)]
    string Name
);

#endregion

public static class RoleEndpoints
{
    public static WebApplication MapRoleEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/roles", async (
            [FromBody] CreateRoleRequest request,
            [FromServices] RoleManager<IdentityRole<Guid>> roleManager) =>
        {
            if (await roleManager.RoleExistsAsync(request.Name))
                return Results.Conflict(
                    "Role already exists.");

            var role =
                new IdentityRole<Guid>(request.Name);

            var result =
                await roleManager.CreateAsync(role);

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

            return Results.Created(
                $"/auth/roles/{role.Id}",
                new
                {
                    role.Id,
                    role.Name
                });
        })
        .WithTags("Roles")
        .WithSummary("Create a role")
        .WithDescription("Creates a new Identity role.")
        .Produces(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status409Conflict)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapPost("/auth/users/{userId:guid}/roles/{roleName}", async (
                Guid userId,
                string roleName,
                [FromServices] UserManager<User> userManager,
                [FromServices] RoleManager<IdentityRole<Guid>> roleManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound(
                    "User not found.");

            if (!await roleManager.RoleExistsAsync(roleName))
                return Results.NotFound(
                    "Role not found.");

            if (await userManager.IsInRoleAsync(
                    user,
                    roleName))
            {
                return Results.Conflict(
                    "User already has this role.");
            }

            var result =
                await userManager.AddToRoleAsync(
                    user,
                    roleName);

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
        })
        .WithTags("Roles")
        .WithSummary("Assign role to user")
        .WithDescription("Assigns an existing Identity role to the specified user.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status409Conflict)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapDelete("/auth/users/{userId:guid}/roles/{roleName}", async (
                Guid userId,
                string roleName,
                [FromServices] UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound(
                    "User not found.");

            if (!await userManager.IsInRoleAsync(
                    user,
                    roleName))
            {
                return Results.NotFound(
                    "User does not have this role.");
            }

            var result =
                await userManager.RemoveFromRoleAsync(
                    user,
                    roleName);

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
        })
        .WithTags("Roles")
        .WithSummary("Remove role from user")
        .WithDescription("Removes an Identity role from the specified user.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status404NotFound)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapGet("/auth/users/{userId:guid}/roles", async (
                Guid userId,
                [FromServices] UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound();

            var roles =
                await userManager.GetRolesAsync(user);

            return Results.Ok(roles);
        })
        .WithTags("Roles")
        .WithSummary("Get user roles")
        .WithDescription("Returns all Identity roles assigned to the specified user.")
        .Produces<IList<string>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();

        return app;
    }
}