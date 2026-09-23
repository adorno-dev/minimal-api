using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.External.Google;

public static class GoogleStartEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/google", Handle)
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Google")
        .WithDescription("Redirects the user to Google for authentication.");
    }

    private static async Task<IResult> Handle(
        IConfiguration config,
        MinimalDbContext context)
    {
        var state = Guid.NewGuid().ToString();
        var pkceVerifier = ExternalPkceGenerator.GeneratePkceVerifier();
        var pkceChallenge = ExternalPkceGenerator.GeneratePkceChallenge(pkceVerifier);

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
    }
}