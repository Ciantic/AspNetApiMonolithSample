namespace AspNetApiMonolithSample.EntityFramework
{
    public class AppDbInitProd : IInitDatabase
    {
        private readonly AppDbContext db;

        public AppDbInitProd(AppDbContext _db)
        {
            db = _db;
        }

        public void Init()
        {
            // TODO: Migrations
            // TODO: Validate schema
        }
    }
}