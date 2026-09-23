using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.External.Facebook;

public static class FacebookStartEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/facebook", HandleAsync)
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Facebook");
    }

    private static async Task<IResult> HandleAsync(
        IConfiguration config,
        MinimalDbContext context)
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
    }

}