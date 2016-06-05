using System.Collections.Generic;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbContext : OpenIddictContext<User, OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken, Role, string>
    {
        public DbSet<Thingie> Thingies { get; set; }

        public AppDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}
