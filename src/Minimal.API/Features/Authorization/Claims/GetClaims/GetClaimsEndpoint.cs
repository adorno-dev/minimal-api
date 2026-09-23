using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Features.Authorization.Claims.GetClaims;

public static class GetClaimsEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/users/{userId:guid}/claims", HandleAsync)
           .WithTags("Claims")
           .WithSummary("Get user claims")
           .WithDescription("Returns all custom Identity claims assigned to the specified user.")
           .Produces<IEnumerable<ClaimResponse>>(StatusCodes.Status200OK)
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

        var claims = await userManager.GetClaimsAsync(user);

        return Results.Ok(
            claims.Select(x => new
            {
                x.Type,
                x.Value
            }));
    }
}