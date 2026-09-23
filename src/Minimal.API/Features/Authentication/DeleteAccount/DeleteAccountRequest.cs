using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.DeleteAccount;

public sealed record DeleteAccountRequest
(
    [Required]
    string CurrentPassword
);