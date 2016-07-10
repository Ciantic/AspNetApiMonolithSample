using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using OpenIddict;

namespace AspNetApiMonolithSample.Api.Models
{
    public class User : OpenIddictUser
    {
        public string FullName { get; set; } = "";
    }
}
