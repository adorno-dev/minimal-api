using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Features.Authorization.Claims.RemoveClaim;

public static class RemoveClaimEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapDelete("/auth/users/{userId:guid}/claims", Handle)
           .WithTags("Claims")
           .WithSummary("Remove claim from user")
           .WithDescription("Removes a custom Identity claim from the specified user.")
           .Produces(StatusCodes.Status204NoContent)
           .Produces(StatusCodes.Status404NotFound)
           .ProducesValidationProblem(StatusCodes.Status400BadRequest)
           .RequireAuthorization();
    }

    private static async Task<IResult> Handle(
        Guid userId,
        [FromBody] RemoveClaimRequest request,
        [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());

        if (user is null)
            return Results.NotFound();

        var claim = new Claim(request.Type, request.Value);

        var result = await userManager.RemoveClaimAsync(user, claim);

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