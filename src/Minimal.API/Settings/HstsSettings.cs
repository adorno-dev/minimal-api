namespace Minimal.API.Settings;

public static class HstsSettings
{
    public static WebApplicationBuilder ConfigureHstsSettings(this WebApplicationBuilder builder)
    {
        builder.Services.AddHsts(options =>
        {
            options.MaxAge = TimeSpan.FromDays(365);
            options.IncludeSubDomains = true;
            options.Preload = true;
        });

        return builder;
    }

    public static WebApplication UseHstsSettings(this WebApplication app)
    {
        if (app.Environment.IsProduction())
            app.UseHsts();

        return app;
    }
}