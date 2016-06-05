using System.Linq;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbInitDev : IInitDatabase
    {
        private readonly AppDbContext db;
        private readonly UserManager<User> userManager;

        public AppDbInitDev(AppDbContext db, UserManager<User> userManager)
        {
            this.db = db;
            this.userManager = userManager;
        }

        public async Task InitAsync()
        {
            await db.Database.EnsureCreatedAsync();
            await userManager.CreateAsync(new User
            {
                Email = "test@example.com",
                UserName = "test@example.com",
            }, "!Test1");
            
            db.Add(new Thingie
            {
                Name = "Thingie one",
            });
            db.Add(new Thingie
            {
                Name = "Hello",
            });
            db.Add(new OpenIddictApplication {
                Id = "official-docs",
                DisplayName = "Docs",
                RedirectUri = "http://localhost:5000/docs/o2c.html",
                LogoutRedirectUri = "http://localhost:5000/docs/index.html",
                Secret = CryptoHelper.Crypto.HashPassword("docs"),
                Type = OpenIddictConstants.ClientTypes.Public,
            });
            await db.SaveChangesAsync();
        }
    }
}