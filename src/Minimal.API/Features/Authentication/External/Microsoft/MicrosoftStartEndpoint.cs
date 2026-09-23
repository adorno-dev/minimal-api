using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Features.Authentication.External.Microsoft;

public static class MicrosoftStartEndpoint
{
    public static void Map(IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/external/microsoft", Handle)
        .WithTags("External Authentication")
        .WithSummary("Authenticate with Microsoft");
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
    }
}