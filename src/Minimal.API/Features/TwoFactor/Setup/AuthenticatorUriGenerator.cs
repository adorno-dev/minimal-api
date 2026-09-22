namespace Minimal.API.Features.TwoFactor.Setup;

internal static class AuthenticatorUriGenerator
{
    private const string Issuer = "Minimal.API";

    public static string Generate(string email, string key)
    {
        return "otpauth://totp/" +
               $"{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(email)}" +
               $"?secret={Uri.EscapeDataString(key)}" +
               $"&issuer={Uri.EscapeDataString(Issuer)}" +
               "&digits=6" +
               "&period=30";
    }
}