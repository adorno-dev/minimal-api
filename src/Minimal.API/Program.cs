
using Minimal.API.Features.Authentication;
using Minimal.API.Features.Authorization;
using Minimal.API.Features.General;
using Minimal.API.Services;
using Minimal.API.Settings;

var builder = WebApplication.CreateBuilder(args);

builder.ConfigureResendSettings()
       .ConfigureHstsSettings()
       .ConfigureDatabaseSettings()
       .ConfigureIdentitySettings()
       .ConfigureJwtSettings()
       .ConfigureCorsSettings()
       .ConfigureOpenApiSettings();

builder.Services.AddValidation()
                .AddAuthorization()
                .AddScoped<EmailService>()
                .AddScoped<TokenService>();

var app = builder.Build();

app.UseOpenApiSettings()
   .UseHstsSettings()
   .UseCorsSettings()
   .UseHttpsRedirection()
   .UseAuthentication()
   .UseAuthorization();

app.MapAuthenticationEndpoints()
   .MapAuthorizationEndpoints()
   .MapGeneralEndpoints();

app.Run();