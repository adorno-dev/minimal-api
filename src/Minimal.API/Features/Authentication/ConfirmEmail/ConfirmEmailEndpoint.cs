using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.ConfirmEmail;

public static class ConfirmEmailEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/confirm-email", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Confirm email")
        .WithDescription("Confirms a user's email address using the confirmation token.")
        .Produces(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest);
    }

    private static async Task<IResult> HandleAsync(
        ConfirmEmailRequest request,
        UserManager<User> userManager)
    {
        var user = await userManager.FindByEmailAsync(request.Email);

        if (user is null)
            return Results.BadRequest();

        var result =
            await userManager.ConfirmEmailAsync(
                user,
                request.Token);

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