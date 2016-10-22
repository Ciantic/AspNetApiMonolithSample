using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Models;
using AspNetApiMonolithSample.Api.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AspNetApiMonolithSample.Api.Mvc;

namespace AspNetApiMonolithSample.Api.Controllers.Frontend
{
    [Authorize]
    [Route("Frontend/[controller]")]
    public class ThingiesController
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
        public int GetOwnedThingie([RequestClaim(AspNetApiMonolithSampleConstants.Claims.OwnsThingie)] int thingieId)
        {
            return thingieId;
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