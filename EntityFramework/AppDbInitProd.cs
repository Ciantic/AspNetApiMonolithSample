using System.Threading.Tasks;

namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbInitProd : IInitDatabase
    {
        private readonly AppDbContext db;

        public AppDbInitProd(AppDbContext _db)
        {
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