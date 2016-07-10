using System.Threading;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Models;

namespace AspNetApiMonolithSample.Api.Stores
{
    public interface IThingieStore : IEntityStore<Thingie, int>
    {
        Task<Thingie> FindByNameAsync(string name, CancellationToken cancellationToken = default(CancellationToken));
    }
}