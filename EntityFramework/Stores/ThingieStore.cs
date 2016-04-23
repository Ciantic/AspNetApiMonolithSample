using System.Threading;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Stores;
using AspNetApiMonolithSample.Models;

namespace AspNetApiMonolithSample.EntityFramework.Stores
{
    public class ThingieStore : EntityStore<Thingie, int>, IThingieStore
    {
        public ThingieStore(AppDbContext dbContext) : base(dbContext)
        {

        }

        public async Task<Thingie> FindByNameAsync(string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            return await DbSet.FirstOrNotFoundExceptionAsync(t => t.Name == name, cancellationToken);
        }
    }
}
