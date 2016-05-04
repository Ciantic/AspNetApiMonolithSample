using System.Threading;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;

namespace AspNetApiMonolithSample.Stores
{
    public interface IThingieStore : IEntityStore<Thingie, int>
    {
        Task<Thingie> FindByNameAsync(string name, CancellationToken cancellationToken = default(CancellationToken));
    }
}