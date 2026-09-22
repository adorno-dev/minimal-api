using Minimal.API.Endpoints;
using Minimal.API.Features.Authorization;
using Minimal.API.Features.General;
using Minimal.API.Services;
using Minimal.API.Settings;

var builder = WebApplication.CreateBuilder(args);

builder.ConfigureResendSettings();
builder.ConfigureHstsSettings();
builder.ConfigureDatabaseSettings();
builder.ConfigureIdentitySettings();
builder.ConfigureJwtSettings();
builder.ConfigureCorsSettings();
builder.ConfigureOpenApiSettings();

builder.Services.AddValidation();
builder.Services.AddAuthorization();

builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<TokenService>();

var app = builder.Build();

app.UseOpenApiSettings();
app.UseHstsSettings();
app.UseCorsSettings();
app.UseHttpsRedirection();
app.UseAuthentication()
   .UseAuthorization();

app.MapAuthenticationEndpoints();
app.MapTwoFactorEndpoints();
app.MapExternalGoogleEndpoints();
app.MapExternalMicrosoftEndpoints();
app.MapExternalFacebookEndpoints();
// app.MapRoleEndpoints();
// app.MapClaimEndpoints();
app.MapAuthorizationEndpoints();

// app.MapDefaultEndpoints();
app.MapGeneralEndpoints();

app.Run();