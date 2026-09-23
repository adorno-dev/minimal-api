using System.ComponentModel.DataAnnotations;

namespace Minimal.API.Features.Authentication.Register;

public sealed record RegisterRequest
(
    [Required]
    [MinLength(3)]
    [MaxLength(30)]
    string Username,

    [Required]
    [EmailAddress]
    string Email,

    [Required]
    string Password,

    [Required]
    string ConfirmPassword

) : IValidatableObject
{
    public IEnumerable<ValidationResult>
    Validate(
        ValidationContext validationContext)
    {
        if (Password != ConfirmPassword)
        {
            yield return new ValidationResult(
                new CompareAttribute(
                    nameof(Password))
                    .FormatErrorMessage(
                        nameof(ConfirmPassword)),
                [nameof(ConfirmPassword)]);
        }
    }
}