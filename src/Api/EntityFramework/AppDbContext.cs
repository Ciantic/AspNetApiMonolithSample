using System.Collections.Generic;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict;
using System;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbContext : OpenIddictContext<User, Role>
    {
        public DbSet<Thingie> Thingies { get; set; }

        public AppDbContext(DbContextOptions options) : base(options)
        {
        }
    }
}