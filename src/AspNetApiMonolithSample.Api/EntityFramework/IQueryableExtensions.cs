using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq.Expressions;
using System;

namespace AspNetApiMonolithSample.Api.EntityFramework
{
    public static class IQueryableExtensions
    {
        public static async Task<T> FirstOrNotFoundExceptionAsync<T>(this IQueryable<T> query, Expression<Func<T, bool>> predicate, CancellationToken cancellationToken = default(CancellationToken))
        {
            return await query.Where(predicate).FirstOrNotFoundExceptionAsync(cancellationToken);
        }
        public static async Task<T> FirstOrNotFoundExceptionAsync<T>(this IQueryable<T> query, CancellationToken cancellationToken = default(CancellationToken))
        {
            var value = await query.FirstOrDefaultAsync(cancellationToken);
            if (value == null)
            {
                throw new EntityNotFoundException();
            }
            else
            {
                return value;
            }
        }

        public static async Task<List<T>> ToListOrEmptyExceptionAsync<T>(this IQueryable<T> query, CancellationToken cancellationToken = default(CancellationToken))
        {
            var value = await query.ToListAsync(cancellationToken);
            if (value == null || value.Count == 0)
            {
                throw new EntityListEmptyException();
            }
            else
            {
                return value;
            }
        }

    }
}