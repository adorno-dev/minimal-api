using Microsoft.AspNetCore.Identity;

namespace Minimal.API.Features.Shared.Extensions;

public static class IdentityResultExtensions
{
    public static IResult ToValidationProblem(this IdentityResult result)
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
}