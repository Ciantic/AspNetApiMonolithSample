using System.Threading;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Stores;
using AspNetApiMonolithSample.Api.Models;

namespace AspNetApiMonolithSample.Api.EntityFramework.Stores
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
