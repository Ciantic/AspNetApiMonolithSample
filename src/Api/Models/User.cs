using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using OpenIddict;

namespace AspNetApiMonolithSample.Models
{
    public class User : OpenIddictUser<OpenIddictAuthorization<OpenIddictToken<int>, int>, OpenIddictToken<int>, int>
    {

    }
}
