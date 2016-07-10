using Microsoft.Extensions.Options;
using OpenIddict;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.EntityFramework
{
    public class AppDbInitProd : IInitDatabase
    {
        private readonly AppDbContext db;
        private readonly List<OpenIddictApplication> apps;

        public AppDbInitProd(AppDbContext _db, IOptions<List<OpenIddictApplication>> apps)
        {
            this.apps = apps.Value;
            db = _db;
        }

        public Task InitAsync()
        {
            return Task.FromResult(0);
            // TODO: Migrations
            // TODO: Validate schema
        }
    }
}