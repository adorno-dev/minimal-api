using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Features.Authentication.External.Facebook;

public static class FacebookCallbackEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/facebook/callback", Handle)
        .WithTags("External Authentication")
        .WithSummary("Complete Facebook authentication");
    }

    private static async Task<IResult> Handle(
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

        var clientId = config["Authentication:Facebook:ClientId"]!;
        var clientSecret = config["Authentication:Facebook:ClientSecret"]!;
        var redirectUri = $"{config["App:BaseURL"]!}/auth/external/facebook/callback";

        // Facebook NÃO usa code_verifier!
        using var http = new HttpClient();
        
        // Token endpoint diferente - é GET, não POST
        var tokenUrl = 
            $"https://graph.facebook.com/v18.0/oauth/access_token?" +
            $"client_id={Uri.EscapeDataString(clientId)}" +
            $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
            $"&client_secret={Uri.EscapeDataString(clientSecret)}" +
            $"&code={Uri.EscapeDataString(code)}";

        var tokenResponse = await http.GetAsync(tokenUrl);
        tokenResponse.EnsureSuccessStatusCode();

        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonDocument.Parse(tokenJson).RootElement;
        var accessToken = tokenData.GetProperty("access_token").GetString()!;

        // Pega informações do usuário
        var userInfoUrl = 
            $"https://graph.facebook.com/me?" +
            $"fields=id,name,email" +
            $"&access_token={Uri.EscapeDataString(accessToken)}";

        var userInfoResponse = await http.GetAsync(userInfoUrl);
        userInfoResponse.EnsureSuccessStatusCode();

        var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
        var userInfo = JsonDocument.Parse(userInfoJson).RootElement;

        var providerUserId = userInfo.GetProperty("id").GetString()!;
        var name = userInfo.GetProperty("name").GetString()!;
        
        // Facebook pode não retornar email se o usuário não autorizou
        var email = userInfo.TryGetProperty("email", out var emailProp) 
            ? emailProp.GetString()! 
            : $"{providerUserId}@facebook.com";

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
        var existingLogin = await userManager.FindByLoginAsync("Facebook", providerUserId);
        if (existingLogin == null)
        {
            var loginInfo = new UserLoginInfo("Facebook", providerUserId, "Facebook");
            await userManager.AddLoginAsync(user, loginInfo);
        }

        var tokenResponseFinal = await tokenService.CreateTokenResponse(user, context, userManager);
        return Results.Ok(tokenResponseFinal);
    }
}