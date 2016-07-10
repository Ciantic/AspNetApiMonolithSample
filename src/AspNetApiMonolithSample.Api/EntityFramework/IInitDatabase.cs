using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.EntityFramework
{
    public interface IInitDatabase
    {
        Task InitAsync();
    }
}