using System.Linq;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict;
using System;
using Microsoft.Extensions.Options;
using System.Collections.Generic;

namespace AspNetApiMonolithSample.Api.EntityFramework
{
    public class AppDbInitDev : IInitDatabase
    {
        private readonly AppDbContext db;
        private readonly UserManager<User> userManager;
        private readonly Dictionary<string, OpenIddictApplication> apps;

        public AppDbInitDev(AppDbContext db, UserManager<User> userManager, IOptions<Dictionary<string, OpenIddictApplication>> apps)
        {
            this.db = db;
            this.userManager = userManager;
            this.apps = apps.Value;
        }

        public async Task InitAsync()
        {
            await db.Database.EnsureCreatedAsync();
            await userManager.CreateAsync(new User
            {
                Email = "test@example.com",
                UserName = "test@example.com",
                EmailConfirmed = true,
            }, "!Test1");
            
            db.Add(new Thingie
            {
                Name = "Thingie one",
            });
            db.Add(new Thingie
            {
                Name = "Hello",
            });
            foreach (var app in apps)
            {
                db.Add(app.Value);
            }
            await db.SaveChangesAsync();
        }
    }
}