using Microsoft.AspNetCore.Identity;

namespace Minimal.API.Models;

public sealed class User : IdentityUser<Guid> {}