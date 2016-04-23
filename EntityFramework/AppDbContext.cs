using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbContext : IdentityDbContext<User, Role, int>
    {
        public DbSet<Thingie> Thingies { get; set; }

        public AppDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}
