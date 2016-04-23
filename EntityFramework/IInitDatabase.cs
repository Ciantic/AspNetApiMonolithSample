using System.Threading.Tasks;

namespace AspNetApiMonolithSample.EntityFramework
{
    public interface IInitDatabase
    {
        Task InitAsync();
    }
}