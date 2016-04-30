using System;
using System.Linq;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;

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
            await db.SaveChangesAsync();
        }
    }
}