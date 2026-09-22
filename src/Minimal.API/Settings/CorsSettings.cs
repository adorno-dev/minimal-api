namespace Minimal.API.Settings;

public static class CorsSettings
{
    public static WebApplicationBuilder ConfigureCorsSettings(this WebApplicationBuilder builder)
    {
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });

        return builder;
    }

    public static WebApplication UseCorsSettings(this WebApplication app)
    {
        app.UseCors();

        return app;
    }
}