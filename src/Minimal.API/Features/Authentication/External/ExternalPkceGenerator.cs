using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Minimal.API.Features.Authentication.External;

public class ExternalPkceGenerator
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

    internal static string GeneratePkceVerifier()
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

    internal static string GeneratePkceChallenge(string verifier)
    {
        var verifierBytes = Encoding.UTF8.GetBytes(verifier); // 1 aloc, aceitável
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(verifierBytes, hash);

        Span<char> chars = stackalloc char[Base64UrlMaxLength(32)];
        if (!Base64Url.TryEncodeToChars(hash, chars, out int written))
            throw new InvalidOperationException("Failed to encode PKCE challenge.");

        return new string(chars[..written]);
    }
}