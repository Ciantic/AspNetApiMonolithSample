using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;
using AspNetApiMonolithSample.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNetApiMonolithSample.Controllers
{
    [Authorize]
    [Route("[controller]")]
    public class ThingiesController : ControllerBase
    {
        private readonly IThingieStore thingies;

        public ThingiesController(IThingieStore thingies)
        {
            this.thingies = thingies;
        }

        public class GetByNameAction
        {
            public string Name { get; set; } = "";
        }

        [HttpPost("[action]")]
        public async Task<Thingie> GetByName([FromBody] GetByNameAction a)
        {
            return await thingies.FindByNameAsync(a.Name);
        }

        public class GetByIdAction
        {
            public int Id { get; set; } = 0;
        }

        [HttpPost("[action]")]
        public async Task<Thingie> GetById([FromBody] GetByIdAction byId)
        {
            return await thingies.FindByIdAsync(byId.Id);
        }

        public class StoreThingie
        {
            [Required]
            public Thingie Thingie { get; set; }
        }

        [HttpPost("[action]")]
        public Thingie Store([FromBody] StoreThingie store)
        {
            return store.Thingie;
        }
    }
}