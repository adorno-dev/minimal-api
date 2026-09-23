using System.Text.Json;

namespace Minimal.API.Features.Authentication.External;

public static class ExternalHelpers
{
    private static readonly HttpClient http = new();

    internal static async Task<JsonElement> ExchangeCodeForToken(
        string code,
        string pkceVerifier,
        string tokenEndpoint,
        string clientId,
        string clientSecret,
        string redirectUri)
    {
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

    internal static async Task<JsonElement> GetUserInfo(string accessToken, string userInfoEndpoint)
    {
        http.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await http.GetAsync(userInfoEndpoint);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(json).RootElement;
    }
}