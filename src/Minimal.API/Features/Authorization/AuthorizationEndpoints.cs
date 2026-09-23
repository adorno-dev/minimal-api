using Minimal.API.Features.Authorization.Claims.AddClaim;
using Minimal.API.Features.Authorization.Claims.GetClaims;
using Minimal.API.Features.Authorization.Claims.RemoveClaim;
using Minimal.API.Features.Authorization.Roles.AssignRole;
using Minimal.API.Features.Authorization.Roles.CreateRole;
using Minimal.API.Features.Authorization.Roles.GetUserRoles;
using Minimal.API.Features.Authorization.Roles.RemoveRole;

namespace Minimal.API.Features.Authorization;

public static class AuthorizationEndpoints
{
    public static IEndpointRouteBuilder MapAuthorizationEndpoints(this IEndpointRouteBuilder app)
    {
        // Roles
        CreateRoleEndpoint.Map(app);
        AssignRoleEndpoint.Map(app);
        RemoveRoleEndpoint.Map(app);
        GetUserRolesEndpoint.Map(app);

        // Claims
        AddClaimEndpoint.Map(app);
        GetClaimsEndpoint.Map(app);
        RemoveClaimEndpoint.Map(app);

        return app;
    }
}