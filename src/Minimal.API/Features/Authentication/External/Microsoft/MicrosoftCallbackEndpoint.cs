using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.External.Microsoft;

public static class MicrosoftCallbackEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/microsoft/callback", HandleAsync)
        .WithTags("External Authentication")
        .WithSummary("Complete Microsoft authentication");
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

        var clientId = config["Authentication:Microsoft:ClientId"]!;
        var clientSecret = config["Authentication:Microsoft:ClientSecret"]!;
        var redirectUri = $"{config["App:BaseURL"]!}/auth/external/microsoft/callback";

        var tokenData = await ExternalHelpers.ExchangeCodeForToken(
            code,
            oauthState.PkceVerifier,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            clientId,
            clientSecret,
            redirectUri);

        var accessToken = tokenData.GetProperty("access_token").GetString()!;

        var userInfo = await ExternalHelpers.GetUserInfo(
            accessToken,
            "https://graph.microsoft.com/v1.0/me");

        // Microsoft devolve: id, mail (ou userPrincipalName), displayName
        var providerUserId = userInfo.GetProperty("id").GetString()!;
        
        // Tenta pegar mail, se não tiver, usa userPrincipalName
        var email = userInfo.TryGetProperty("mail", out var mail) 
            ? mail.GetString()! 
            : userInfo.GetProperty("userPrincipalName").GetString()!;

        // Tenta pegar displayName, se não tiver, usa "Microsoft User"
        var name = userInfo.TryGetProperty("displayName", out var displayName) 
            ? displayName.GetString()! 
            : "Microsoft User";

        // Busca ou cria usuário
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

        // Vincula login externo
        var existingLogin = await userManager.FindByLoginAsync("Microsoft", providerUserId);
        if (existingLogin == null)
        {
            var loginInfo = new UserLoginInfo("Microsoft", providerUserId, "Microsoft");
            await userManager.AddLoginAsync(user, loginInfo);
        }

        var tokenResponse = await tokenService.CreateTokenResponse(user, context, userManager);
        return Results.Ok(tokenResponse);
    }
}