using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi;

namespace Minimal.API.Settings;

public static class OpenApiSettings
{
    public static WebApplicationBuilder ConfigureOpenApiSettings(this WebApplicationBuilder builder)
    {
        if (builder.Environment.IsDevelopment())
        {
            builder.Services.AddOpenApi(options =>
            {
                options.AddDocumentTransformer(
                    (document, context, cancellationToken) =>
                    {
                        document.Components ??= new();

                        document.Components.SecuritySchemes ??=
                            new Dictionary<string, IOpenApiSecurityScheme>();

                        document.Components.SecuritySchemes["Bearer"] =
                            new OpenApiSecurityScheme
                            {
                                Type = SecuritySchemeType.Http,
                                Scheme = "bearer",
                                BearerFormat = "JWT"
                            };

                        return Task.CompletedTask;
                    });

                options.AddOperationTransformer(
                    (operation, context, cancellationToken) =>
                    {
                        if (context.Description.ActionDescriptor
                            .EndpointMetadata
                            .OfType<IAuthorizeData>()
                            .Any())
                        {
                            operation.Security ??= [];

                            operation.Security.Add(
                                new OpenApiSecurityRequirement
                                {
                                    [
                                        new OpenApiSecuritySchemeReference(
                                            "Bearer",
                                            context.Document)
                                    ] = []
                                });
                        }

                        return Task.CompletedTask;
                    });
            });
        }

        return builder;
    }

    public static WebApplication UseOpenApiSettings(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();

            app.UseSwaggerUI(options =>
                options.SwaggerEndpoint(
                    "/openapi/v1.json",
                    "Minimal API v1.0"));
        }

        return app;
    }
}