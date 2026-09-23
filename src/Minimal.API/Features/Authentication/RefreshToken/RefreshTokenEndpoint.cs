using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Minimal.API.Data;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.RefreshToken;

public static class RefreshTokenEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/refresh", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Refresh access token")
        .WithDescription(
            "Rotates a valid refresh token and returns a new access token " +
            "and refresh token.")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> HandleAsync(
        TokenService tokenService,
        [FromBody] RefreshTokenRequest request,
        [FromServices] MinimalDbContext context,
        [FromServices] UserManager<User> userManager)
    {
        var response = await tokenService.RotateRefreshToken(
            request.RefreshToken,
            context,
            userManager);

        return response is null
            ? Results.Unauthorized()
            : Results.Ok(response);
    }
}