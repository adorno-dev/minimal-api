using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.UpdateProfile;

public sealed record UpdateProfileRequest
(
    [Phone]
    string? PhoneNumber
);