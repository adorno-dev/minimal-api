using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ResetPassword;

public sealed record ResetPasswordRequest
(
    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Token,

    [Required]
    string NewPassword,

    [Required]
    string ConfirmNewPassword

) : IValidatableObject
{
    public IEnumerable<ValidationResult>
    Validate(
        ValidationContext validationContext)
    {
        if (NewPassword != ConfirmNewPassword)
        {
            yield return new ValidationResult(
                new CompareAttribute(
                    nameof(NewPassword))
                    .FormatErrorMessage(
                        nameof(ConfirmNewPassword)),
                [nameof(ConfirmNewPassword)]);
        }
    }
}