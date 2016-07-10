using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AspNetApiMonolithSample.Stores;
using System.Threading;
using AspNetApiMonolithSample.Models;

namespace AspNetApiMonolithSample.EntityFramework.Stores
{
    abstract public class EntityStore<TEntity, TKey> : IEntityStore<TEntity, TKey>
        where TEntity : class, IEntity<TKey>
        where TKey : IEquatable<TKey>
    {
        private readonly DbContext db;

        public virtual IQueryable<TEntity> Items
        {
            get { return db.Set<TEntity>(); }
        }

        protected virtual DbSet<TEntity> DbSet
        {
            get { return db.Set<TEntity>(); }
        }

        public EntityStore(DbContext dbContext)
        {
            db = dbContext;
        }

        public bool AutoSaveChanges { get; set; } = true;

        private async Task<bool> SaveChanges(CancellationToken cancellationToken)
        {
            if (AutoSaveChanges)
            {
                var res = await db.SaveChangesAsync(cancellationToken);
                return res == 0;
            }
            else
            {
                return false;
            }
        }

        public async Task<bool> DeleteAsync(TEntity entity, CancellationToken cancellationToken = default(CancellationToken))
        {
            db.Remove(entity);
            return await SaveChanges(cancellationToken);
        }

        public async Task<bool> DeleteByIdAsync(TKey id, CancellationToken cancellationToken = default(CancellationToken))
        {
            var entity = await FindByIdAsync(id, cancellationToken);
            db.Remove(entity);
            return await SaveChanges(cancellationToken);
        }

        public async Task<TEntity> FindByIdAsync(TKey id, CancellationToken cancellationToken = default(CancellationToken))
        {
            return await DbSet.FirstOrNotFoundExceptionAsync(f => f.Id.Equals(id), cancellationToken);
        }

        public async Task<TEntity> CreateAsync(TEntity item, CancellationToken cancellationToken = default(CancellationToken))
        {
            var entry = DbSet.Add(item);
            await SaveChanges(cancellationToken);
            return entry.Entity;
        }

        public async Task<TEntity> UpdateAsync(TEntity item, CancellationToken cancellationToken = default(CancellationToken))
        {
            var entry = DbSet.Update(item);
            await SaveChanges(cancellationToken);
            return entry.Entity;
        }
    }
}
