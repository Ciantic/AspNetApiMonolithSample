using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict;
using OpenIddict.Models;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbContext : OpenIddictContext<User, Application<int>, Role, int>
    {
        public DbSet<Thingie> Thingies { get; set; }

        public AppDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}
