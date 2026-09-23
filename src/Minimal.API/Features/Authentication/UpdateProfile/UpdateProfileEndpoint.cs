using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.UpdateProfile;

public static class UpdateProfileEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPut("/auth/profile", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Update profile")
        .WithDescription("Updates the authenticated user's profile information.")
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .Produces(StatusCodes.Status404NotFound)
        .RequireAuthorization();
    }

    private static async Task<IResult> HandleAsync(
        UpdateProfileRequest request,
        ClaimsPrincipal principal,
        UserManager<User> userManager)
    {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId is null)
                return Results.Unauthorized();

            var user = await userManager.FindByIdAsync(userId);

            if (user is null)
                return Results.NotFound();

            var result = await userManager.SetPhoneNumberAsync(user, request.PhoneNumber);

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