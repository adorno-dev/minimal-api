using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Features.Shared.Contracts;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.External.Google;

public static class GoogleCallbackEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/google/callback", HandleAsync)
        .WithTags("External Authentication")
        .WithSummary("Complete Google authentication")
        .WithDescription("Processes the Google authentication callback, resolves or creates the corresponding Identity user, and issues an access token and refresh token.")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized);
    }

    private static async Task<IResult> HandleAsync(
        string code,
        string state,
        TokenService tokenService,
        MinimalDbContext context,
        UserManager<User> userManager,
        IConfiguration config)
    {
        var oauthState = await context.OAuthStates
            .FirstOrDefaultAsync(x => x.State == state && !x.IsUsed);

        if (oauthState == null)
            return Results.BadRequest("Invalid or expired state");

        oauthState.IsUsed = true;
        await context.SaveChangesAsync();

        // ============================================
        // USANDO AS FUNÇÕES GENÉRICAS
        // ============================================
        var clientId = config["Authentication:Google:ClientId"]!;
        var clientSecret = config["Authentication:Google:ClientSecret"]!;
        var redirectUri = $"{config["App:BaseURL"]!}/auth/external/google/callback";

        var tokenData = await ExternalHelpers.ExchangeCodeForToken(
            code,
            oauthState.PkceVerifier,
            "https://oauth2.googleapis.com/token",
            clientId,
            clientSecret,
            redirectUri);

        var accessToken = tokenData.GetProperty("access_token").GetString()!;

        var userInfo = await ExternalHelpers.GetUserInfo(
            accessToken,
            "https://www.googleapis.com/oauth2/v2/userinfo");

        var email = userInfo.GetProperty("email").GetString()!;
        var providerUserId = userInfo.GetProperty("id").GetString()!;
        var name = userInfo.GetProperty("name").GetString()!;

        // ============================================
        // RESTO IGUAL
        // ============================================
        var user = await userManager.FindByEmailAsync(email);
        if (user == null)
        {
            user = new User
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true
            };
            await userManager.CreateAsync(user);
        }

        var existingLogin = await userManager.FindByLoginAsync("Google", providerUserId);
        if (existingLogin == null)
        {
            var loginInfo = new UserLoginInfo("Google", providerUserId, "Google");
            await userManager.AddLoginAsync(user, loginInfo);
        }

        var tokenResponse = await tokenService.CreateTokenResponse(user, context, userManager);
        return Results.Ok(tokenResponse);
    }
}