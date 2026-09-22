using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Services;

#region +Responses

public sealed record TokenResponse
(
    string AccessToken,
    string RefreshToken
);

#endregion

internal class TokenService(IConfiguration configuration)
{
    private IConfigurationSection jwt = configuration.GetSection("JWT");

    private void CreateAccessToken(
        User user,
        IList<string> roles,
        IList<Claim> userClaims,
        out string accessToken)
    {
        var claims =
            new List<Claim>
            {
                new(
                    ClaimTypes.NameIdentifier,
                    user.Id.ToString()),

                new(
                    ClaimTypes.Name,
                    user.UserName!)
            };

        foreach (var role in roles)
        {
            claims.Add(
                new Claim(
                    ClaimTypes.Role,
                    role));
        }

        foreach (var claim in userClaims)
        {
            if (claim.Type is
                ClaimTypes.NameIdentifier or
                ClaimTypes.Name)
            {
                continue;
            }

            claims.Add(
                new Claim(
                    claim.Type,
                    claim.Value));
        }

        var key =
            new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwt["Key"]!));

        var credentials =
            new SigningCredentials(
                key,
                SecurityAlgorithms.HmacSha256);

        var token =
            new JwtSecurityToken(
                issuer: jwt["Issuer"],
                audience: jwt["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    double.Parse(
                        jwt["ExpiresInMinutes"]!)),
                signingCredentials: credentials);

        accessToken =
            new JwtSecurityTokenHandler()
                .WriteToken(token);
    }

    private void CreateRefreshToken(
        out string refreshToken,
        out byte[] refreshTokenHash)
    {
        refreshToken =
            Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(64));

        refreshTokenHash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(refreshToken));
    }

    internal async Task<TokenResponse?> RotateRefreshToken(
        string refreshToken,
        MinimalDbContext context,
        UserManager<User> userManager)
    {
        var hash =
            SHA256.HashData(
                Encoding.UTF8.GetBytes(refreshToken));

        await using var transaction =
            await context.Database
                .BeginTransactionAsync();

        var token =
            await context.RefreshTokens
                .Include(x => x.User)
                .FirstOrDefaultAsync(
                    x =>
                        x.TokenHash == hash &&
                        x.ExpiresAt > DateTime.UtcNow);

        if (token is null)
            return null;

        var user =
            token.User;

        var roles =
            await userManager.GetRolesAsync(user);

        var userClaims =
            await userManager.GetClaimsAsync(user);

        CreateAccessToken(
            user,
            roles,
            userClaims,
            out var accessToken);

        CreateRefreshToken(
            out var newRefreshToken,
            out var newRefreshTokenHash);

        context.RefreshTokens.Remove(token);

        context.RefreshTokens.Add(
            new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                TokenHash = newRefreshTokenHash,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            });

        await context.SaveChangesAsync();

        await transaction.CommitAsync();

        return new TokenResponse(
            accessToken,
            newRefreshToken);
    }

    internal async Task<TokenResponse> CreateTokenResponse(
        User user,
        MinimalDbContext context,
        UserManager<User> userManager)
    {
        var roles =
            await userManager.GetRolesAsync(user);

        var userClaims =
            await userManager.GetClaimsAsync(user);

        CreateAccessToken(
            user,
            roles,
            userClaims,
            out var accessToken);

        CreateRefreshToken(
            out var refreshToken,
            out var refreshTokenHash);

        context.RefreshTokens.Add(
            new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                TokenHash = refreshTokenHash,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            });

        await context.SaveChangesAsync();

        return new TokenResponse(
            accessToken,
            refreshToken);
    }
}