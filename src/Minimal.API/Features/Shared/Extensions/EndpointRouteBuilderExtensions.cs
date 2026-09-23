namespace Minimal.API.Features.Shared.Extensions;

public static class EndpointRouteBuilderExtensions
{
    public static bool IsDevelopment(this IEndpointRouteBuilder app) =>
        app.ServiceProvider.GetRequiredService<IHostEnvironment>().IsDevelopment();

    public static bool IsProduction(this IEndpointRouteBuilder app) =>
        app.ServiceProvider.GetRequiredService<IHostEnvironment>().IsProduction();
}