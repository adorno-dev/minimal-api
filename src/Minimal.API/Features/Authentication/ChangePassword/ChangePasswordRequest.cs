using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.ChangePassword;

public sealed record ChangePasswordRequest
(
    [Required]
    string CurrentPassword,

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