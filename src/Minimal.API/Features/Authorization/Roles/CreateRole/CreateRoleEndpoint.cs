using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Minimal.API.Features.Authorization.Roles.CreateRole;

public static class CreateRoleEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/roles", HandleAsync)
           .WithTags("Roles")
           .WithSummary("Create a role")
           .WithDescription("Creates a new Identity role.")
           .Produces(StatusCodes.Status201Created)
           .Produces(StatusCodes.Status409Conflict)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        [FromBody] CreateRoleRequest request,
        [FromServices] RoleManager<IdentityRole<Guid>> roleManager)
    {
        if (await roleManager.RoleExistsAsync(request.Name))
            return Results.Conflict("Role already exists.");

        var role = new IdentityRole<Guid>(request.Name);

        var result = await roleManager.CreateAsync(role);

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
    }
}