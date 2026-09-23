using Minimal.API.Features.Authentication.ChangeEmail;
using Minimal.API.Features.Authentication.ChangePassword;
using Minimal.API.Features.Authentication.ChangeUsername;
using Minimal.API.Features.Authentication.ConfirmEmail;
using Minimal.API.Features.Authentication.DeleteAccount;
using Minimal.API.Features.Authentication.External;
using Minimal.API.Features.Authentication.ForgotPassword;
using Minimal.API.Features.Authentication.Login;
using Minimal.API.Features.Authentication.Logout;
using Minimal.API.Features.Authentication.RefreshToken;
using Minimal.API.Features.Authentication.Register;
using Minimal.API.Features.Authentication.ResendConfirmation;
using Minimal.API.Features.Authentication.ResetPassword;
using Minimal.API.Features.Authentication.TwoFactor;
using Minimal.API.Features.Authentication.UpdateProfile;
using Minimal.API.Features.Shared.Extensions;

namespace Minimal.API.Features.Authentication;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder app)
    {
        LoginEndpoint.Map(app);
        RegisterEndpoint.Map(app);
        RefreshTokenEndpoint.Map(app);
        LogoutEndpoint.Map(app);
        ForgotPasswordEndpoint.Map(app);
        ResetPasswordEndpoint.Map(app);
        ConfirmEmailLinkEndpoint.Map(app);
        ConfirmEmailEndpoint.Map(app);
        #region ConfirmEmailDevelopmentEndpoint
        if (app.IsDevelopment())
            ConfirmEmailDevelopmentEndpoint.Map(app);
        #endregion
        ResendConfirmationEndpoint.Map(app);
        ChangePasswordEndpoint.Map(app);
        ChangeEmailEndpoint.Map(app);
        ChangeEmailConfirmEndpoint.Map(app);
        DeleteAccountEndpoint.Map(app);
        ChangeUsernameEndpoint.Map(app);
        UpdateProfileEndpoint.Map(app);

        ExternalEndpoints.Map(app);
        TwoFactorEndpoints.Map(app);

        return app;
    }
}