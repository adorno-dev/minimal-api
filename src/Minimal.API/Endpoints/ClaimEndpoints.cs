using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Models;

namespace Minimal.API.Endpoints;

#region +Requests

public sealed record AddClaimRequest
(
    [Required]
    string Type,

    [Required]
    string Value
);

public sealed record RemoveClaimRequest
(
    [Required]
    string Type,

    [Required]
    string Value
);

#endregion

public static class ClaimEndpoints
{
    public static WebApplication MapClaimEndpoints(this WebApplication app)
    {
        app.MapPost("/auth/users/{userId:guid}/claims", async (
                Guid userId,
                [FromBody] AddClaimRequest request,
                [FromServices] UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound();

            var claim =
                new Claim(
                    request.Type,
                    request.Value);

            var result =
                await userManager.AddClaimAsync(
                    user,
                    claim);

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
        .WithTags("Claims")
        .WithSummary("Add claim to user")
        .WithDescription("Adds a custom Identity claim to the specified user.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapGet("/auth/users/{userId:guid}/claims", async (
                Guid userId,
                [FromServices] UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound();

            var claims =
                await userManager.GetClaimsAsync(user);

            return Results.Ok(
                claims.Select(x => new
                {
                    x.Type,
                    x.Value
                }));
        })
        .WithTags("Claims")
        .WithSummary("Get user claims")
        .WithDescription("Returns all custom Identity claims assigned to the specified user.")
        .Produces<IEnumerable<object>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();

        app.MapDelete("/auth/users/{userId:guid}/claims", async (
                Guid userId,
                [FromBody] RemoveClaimRequest request,
                [FromServices] UserManager<User> userManager) =>
        {
            var user =
                await userManager.FindByIdAsync(
                    userId.ToString());

            if (user is null)
                return Results.NotFound();

            var claim =
                new Claim(
                    request.Type,
                    request.Value);

            var result =
                await userManager.RemoveClaimAsync(
                    user,
                    claim);

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
        .WithTags("Claims")
        .WithSummary("Remove claim from user")
        .WithDescription("Removes a custom Identity claim from the specified user.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        return app;
    }
}