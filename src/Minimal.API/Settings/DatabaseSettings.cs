using Microsoft.EntityFrameworkCore;
using Minimal.API.Data;

namespace Minimal.API.Settings;

public static class DatabaseSettings
{
    public static WebApplicationBuilder ConfigureDatabaseSettings(this WebApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

        builder.Services.AddDbContext<MinimalDbContext>(options =>
            options.UseSqlite(connectionString));

        return builder;
    }
}