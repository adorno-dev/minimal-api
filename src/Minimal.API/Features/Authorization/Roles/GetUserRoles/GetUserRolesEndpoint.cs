using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Features.Authorization.Roles.GetUserRoles;

public static class GetUserRolesEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/users/{userId:guid}/roles", HandleAsync)
           .WithTags("Roles")
           .WithSummary("Get user roles")
           .WithDescription("Returns all Identity roles assigned to the specified user.")
           .Produces<IEnumerable<RoleResponse>>(StatusCodes.Status200OK)
           .Produces(StatusCodes.Status404NotFound)
           .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        Guid userId,
        [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());

        if (user is null)
            return Results.NotFound();

        var roles = await userManager.GetRolesAsync(user);

        return Results.Ok(
            roles.Select(r => new RoleResponse(r)));
    }
}