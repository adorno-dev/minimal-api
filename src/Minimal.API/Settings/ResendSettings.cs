using Resend;

namespace Minimal.API.Settings;

public static class ResendSettings
{
    public static WebApplicationBuilder ConfigureResendSettings(this WebApplicationBuilder builder)
    {
        var resend = builder.Configuration.GetSection("Resend");

        builder.Services.AddOptions();
        builder.Services.AddHttpClient<ResendClient>();
        builder.Services.Configure<ResendClientOptions>(options =>
            options.ApiToken = resend["ApiToken"]!);

        builder.Services.AddTransient<IResend, ResendClient>();
        
        return builder;
    }
}