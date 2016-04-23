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

        public void Init()
        {
            db.Database.EnsureCreated();
            var u = new User
            {
                Email = "test@example.com",
                UserName = "test",
            };
            db.Add(u);

            db.Add(new Thingie
            {
                Name = "Thingie one",
            });
            db.Add(new Thingie
            {
                Name = "Hello",
            });
            db.SaveChanges();
            // userManager.AddLoginAsync(u, new UserLoginInfo("password", "password", "password")).Wait();
            // userManager.AddPasswordAsync(u, "testi123").Wait();
        }
    }
}