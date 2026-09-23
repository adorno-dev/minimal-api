using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Features.Authentication.RefreshToken;

namespace Minimal.API.Features.Authentication.Logout;

public static class LogoutEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost("/auth/logout", HandleAsync)
        .WithTags("Authentication")
        .WithSummary("Log out")
        .WithDescription("Invalidates the supplied refresh token.")
        .Produces(StatusCodes.Status204NoContent);
    }

    private static async Task<IResult> HandleAsync(
        RefreshTokenRequest request,
        MinimalDbContext context)
    {
        var hash = SHA256.HashData(
            Encoding.UTF8.GetBytes(request.RefreshToken));

        await context.RefreshTokens
            .Where(x => x.TokenHash == hash)
            .ExecuteDeleteAsync();

        return Results.NoContent();
    }
}