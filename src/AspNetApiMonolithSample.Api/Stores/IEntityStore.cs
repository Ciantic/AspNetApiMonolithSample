using System.Threading;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Stores
{
    public interface IEntityStore<TEntity, TKey>
    {
        Task<TEntity> FindByIdAsync(TKey id, CancellationToken cancellationToken = default(CancellationToken));

        Task<TEntity> CreateAsync(TEntity item, CancellationToken cancellationToken = default(CancellationToken));

        Task<TEntity> UpdateAsync(TEntity item, CancellationToken cancellationToken = default(CancellationToken));

        Task<bool> DeleteByIdAsync(TKey id, CancellationToken cancellationToken = default(CancellationToken));

        Task<bool> DeleteAsync(TEntity entity, CancellationToken cancellationToken = default(CancellationToken));
    }
}