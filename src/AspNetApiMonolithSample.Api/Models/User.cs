using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using OpenIddict;

namespace AspNetApiMonolithSample.Api.Models
{
    public class User : OpenIddictUser
    {
        public string LanguageCode { get; set; } = "";
        public string FistName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string FullName
        {
            get
            {
                return $"{FistName} {LastName}".Trim();
            }
        }
    }
}
