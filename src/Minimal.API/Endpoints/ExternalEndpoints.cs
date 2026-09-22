using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;
using Minimal.API.Models;
using Minimal.API.Services;

namespace Minimal.API.Endpoints;

public static class ExternalEndpoints
{
    // private static string GeneratePkceVerifier()
    // {
    //     var bytes = RandomNumberGenerator.GetBytes(32);
    //     return Convert.ToBase64String(bytes)
    //         .Replace("+", "-")
    //         .Replace("/", "_")
    //         .Replace("=", "");
    // }
    private static int Base64UrlMaxLength(int byteCount) =>
        ((byteCount + 2) / 3) * 4;

    private static string GeneratePkceVerifier()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);

        Span<char> chars = stackalloc char[Base64UrlMaxLength(32)];
        if (!Base64Url.TryEncodeToChars(bytes, chars, out int written))
            throw new InvalidOperationException("Failed to encode PKCE verifier.");

        return new string(chars[..written]);
    }
    // private static string GeneratePkceChallenge(string verifier)
    // {
    //     using var sha256 = SHA256.Create();
    //     var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));
    //     return Convert.ToBase64String(hash)
    //         .Replace("+", "-")
    //         .Replace("/", "_")
    //         .Replace("=", "");
    // }

    private static string GeneratePkceChallenge(string verifier)
    {
        var verifierBytes = Encoding.UTF8.GetBytes(verifier); // 1 aloc, aceitável
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(verifierBytes, hash);

        Span<char> chars = stackalloc char[Base64UrlMaxLength(32)];
        if (!Base64Url.TryEncodeToChars(hash, chars, out int written))
            throw new InvalidOperationException("Failed to encode PKCE challenge.");

        return new string(chars[..written]);
    }

    private static async Task<JsonElement> ExchangeCodeForToken(
        string code,
        string pkceVerifier,
        string tokenEndpoint,
        string clientId,
        string clientSecret,
        string redirectUri)
    {
        using var http = new HttpClient();
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code_verifier", pkceVerifier)
        });

        var response = await http.PostAsync(tokenEndpoint, content);    
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement;
    }

    private static async Task<JsonElement> GetUserInfo(string accessToken, string userInfoEndpoint)
    {
        using var http = new HttpClient();
        http.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await http.GetAsync(userInfoEndpoint);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement;
    }

    public static WebApplication MapExternalGoogleEndpoints(this WebApplication app)
    {
        app.MapGet("/auth/external/google", async (
            IConfiguration config,
            MinimalDbContext context) =>
        {
            var state = Guid.NewGuid().ToString();
            var pkceVerifier = GeneratePkceVerifier();
            var pkceChallenge = GeneratePkceChallenge(pkceVerifier);

            var appBaseUrl = config["App:BaseURL"]!;

            context.OAuthStates.Add(new OAuthState
            {
                Id = Guid.NewGuid(),
                State = state,
                PkceVerifier = pkceVerifier,
                RedirectUrl = appBaseUrl,
                CreatedAt = DateTime.UtcNow,
                IsUsed = false
            });
            await context.SaveChangesAsync();

            var clientId = config["Authentication:Google:ClientId"]!;
            var redirectUri = $"{appBaseUrl}/auth/external/google/callback";

            var authUrl = 
                $"https://accounts.google.com/o/oauth2/v2/auth?" +
                $"client_id={Uri.EscapeDataString(clientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_type=code" +
                $"&scope=email%20profile" +
                $"&code_challenge={Uri.EscapeDataString(pkceChallenge)}" +
                $"&code_challenge_method=S256" +
                $"&state={Uri.EscapeDataString(state)}";

            return Results.Redirect(authUrl);
        })
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Google")
        .WithDescription("Redirects the user to Google for authentication.");


        app.MapGet("/auth/external/google/callback", async (
            string code,
            string state,
            TokenService tokenService,
            MinimalDbContext context,
            UserManager<User> userManager,
            IConfiguration config) =>
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

            var tokenData = await ExchangeCodeForToken(
                code,
                oauthState.PkceVerifier,
                "https://oauth2.googleapis.com/token",
                clientId,
                clientSecret,
                redirectUri);

            var accessToken = tokenData.GetProperty("access_token").GetString()!;

            var userInfo = await GetUserInfo(
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
        })
        .WithTags("External Authentication")
        .WithSummary("Complete Google authentication")
        .WithDescription("Processes the Google authentication callback, resolves or creates the corresponding Identity user, and issues an access token and refresh token.")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized);

        return app;
    }

    public static WebApplication MapExternalMicrosoftEndpoints(this WebApplication app)
    {
        app.MapGet("/auth/external/microsoft", async (
            IConfiguration config,
            MinimalDbContext context) =>
        {
            var state = Guid.NewGuid().ToString();
            var pkceVerifier = GeneratePkceVerifier();
            var pkceChallenge = GeneratePkceChallenge(pkceVerifier);

            var appBaseUrl = config["App:BaseURL"]!;

            context.OAuthStates.Add(new OAuthState
            {
                Id = Guid.NewGuid(),
                State = state,
                PkceVerifier = pkceVerifier,
                RedirectUrl = appBaseUrl,
                CreatedAt = DateTime.UtcNow,
                IsUsed = false
            });
            await context.SaveChangesAsync();

            var clientId = config["Authentication:Microsoft:ClientId"]!;
            var redirectUri = $"{appBaseUrl}/auth/external/microsoft/callback";

            var authUrl = 
                $"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" +
                $"client_id={Uri.EscapeDataString(clientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_type=code" +
                $"&scope={Uri.EscapeDataString("openid email profile User.Read")}" +
                $"&code_challenge={Uri.EscapeDataString(pkceChallenge)}" +
                $"&code_challenge_method=S256" +
                $"&state={Uri.EscapeDataString(state)}";

            return Results.Redirect(authUrl);
        })
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Microsoft");

        app.MapGet("/auth/external/microsoft/callback", async (
            string code,
            string state,
            TokenService tokenService,
            MinimalDbContext context,
            UserManager<User> userManager,
            IConfiguration config) =>
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

            var tokenData = await ExchangeCodeForToken(
                code,
                oauthState.PkceVerifier,
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                clientId,
                clientSecret,
                redirectUri);

            var accessToken = tokenData.GetProperty("access_token").GetString()!;

            var userInfo = await GetUserInfo(
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
        })
        .WithTags("External Authentication")
        .WithSummary("Complete Microsoft authentication");

        return app;
    }

    public static WebApplication MapExternalFacebookEndpoints(this WebApplication app)
    {
        app.MapGet("/auth/external/facebook", async (
            IConfiguration config,
            MinimalDbContext context) =>
        {
            var state = Guid.NewGuid().ToString();

            // Facebook NÃO usa PKCE, então o pkce_verifier fica vazio
            var appBaseUrl = config["App:BaseURL"]!;

            context.OAuthStates.Add(new OAuthState
            {
                Id = Guid.NewGuid(),
                State = state,
                PkceVerifier = "", // Facebook não usa PKCE!
                RedirectUrl = appBaseUrl,
                CreatedAt = DateTime.UtcNow,
                IsUsed = false
            });
            await context.SaveChangesAsync();

            var clientId = config["Authentication:Facebook:ClientId"]!;
            var redirectUri = $"{appBaseUrl}/auth/external/facebook/callback";

            var authUrl = 
                $"https://www.facebook.com/v18.0/dialog/oauth?" +
                $"client_id={Uri.EscapeDataString(clientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&response_type=code" +
                $"&scope=email" +
                $"&state={Uri.EscapeDataString(state)}";

            return Results.Redirect(authUrl);
        })
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Facebook");

        app.MapGet("/auth/external/facebook/callback", async (
            string code,
            string state,
            TokenService tokenService,
            MinimalDbContext context,
            UserManager<User> userManager,
            IConfiguration config) =>
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
        })
        .WithTags("External Authentication")
        .WithSummary("Complete Facebook authentication");

        return app;
    }
}