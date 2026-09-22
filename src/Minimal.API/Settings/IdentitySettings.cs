using Microsoft.AspNetCore.Identity;
using Minimal.API.Data;
using Minimal.API.Models;

namespace Minimal.API.Settings;

public static class IdentitySettings
{
    public static WebApplicationBuilder ConfigureIdentitySettings(this WebApplicationBuilder builder)
    {
        builder.Services
               .AddIdentityCore<User>(options =>
               {
                   options.Lockout.AllowedForNewUsers = true;
                   options.Lockout.MaxFailedAccessAttempts = 5;
                   options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);   
                   options.SignIn.RequireConfirmedEmail = true;
               })
               .AddRoles<IdentityRole<Guid>>()
               .AddSignInManager()
               .AddEntityFrameworkStores<MinimalDbContext>()
               .AddDefaultTokenProviders();
        return builder;
    }
}
