using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using AspNetApiMonolithSample.Api.Mvc;
using Newtonsoft.Json;
using Microsoft.Extensions.Options;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace AspNetApiMonolithSample.Api.Controllers
{
    [Route("[controller]")]
    public class ErrorController : ControllerBase
    {
        private readonly MvcJsonOptions _mvcJsonOptions;
        private readonly UiBrandingHtml _brandingHtml;

        public ErrorController(
            IOptions<UiBrandingHtml> brandingHtml, 
            IOptions<MvcJsonOptions> mvcJsonOptions
        )
        {
            _mvcJsonOptions = mvcJsonOptions.Value;
            _brandingHtml = brandingHtml.Value;
        }

        [HttpGet, HttpPost, HttpHead, HttpDelete, HttpOptions, HttpPatch, HttpPut]
        public IActionResult Error(
            [FromQuery] int status = 0, 
            [FromQuery] string message = ""
        )
        {
            if (HttpContext.Request.Headers.ContainsKey("Accept") &&
                HttpContext.Request.Headers["Accept"].Contains("application/json"))
            {
                if (status == 403)
                {
                    return new Forbidden().GetResult();
                }
                else if (status == 401)
                {
                    return new NotAuthorized().GetResult();
                }
                else if (status == 404)
                {
                    return new NotFound().GetResult();
                }
                else
                {
                    return new UndefinedError().GetResult();
                }
            }

            var data = JsonConvert.SerializeObject(new
            {
                Error = status,
                ErrorMessage = message
            }, _mvcJsonOptions.SerializerSettings);

            return new ContentResult()
            {
                StatusCode = status != 0 ? status : 400,
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_ERROR_PAGE = {data};</script>
                    {_brandingHtml?.Error}
                    </head>
                    <body>
                    <p>{status}: {message}</p>
                    ",
                ContentType = "text/html; charset=utf8"
            };
        }
    }
}
