using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Newtonsoft.Json;
using Swashbuckle.SwaggerUi.Application;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Swagger
{
    public class CustomSwaggerMiddlewareOpts
    {
        public string baseRoute { get; set; }
        public string definitionUrl { get; set; }
        public string oauth2_clientId { get; set; } = "";
        public string oauth2_realms { get; set; } = "";
        public string oauth2_appName { get; set; } = "";
        public string oauth2_clientSecret { get; set; } = "";
        public Dictionary<string, string> oauth2_additionalQueryStringParams { get; set; }
    }

    /// <summary>
    /// Custom swagger index middleware to populate OAuth 2 / OpenId values in the index.html
    /// 
    /// Looks first a wwwroot/baseRoot for a swagger UI, then the Swagger UI manifest.
    /// 
    /// </summary>
    public class CustomSwaggerMiddleware
    {
        private readonly IHostingEnvironment _env;
        private readonly RequestDelegate _next;
        private readonly TemplateMatcher _requestMatcher;
        private readonly Assembly _swaggerAssembly;
        private readonly CustomSwaggerMiddlewareOpts _opts;

        public CustomSwaggerMiddleware(
            RequestDelegate next,
            IHostingEnvironment env,
            CustomSwaggerMiddlewareOpts opts
        )
        {
            _env = env;
            _next = next;
            _opts = opts;            
            _requestMatcher = new TemplateMatcher(TemplateParser.Parse(_opts.baseRoute), new RouteValueDictionary());
            _swaggerAssembly = typeof(SwaggerUiMiddleware).GetTypeInfo().Assembly;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (!RequestingSwaggerUi(httpContext.Request))
            {
                await _next(httpContext);
                return;
            }

            httpContext.Response.StatusCode = 200;
            httpContext.Response.ContentType = "text/html";

            var indexInWwwroot = Path.Combine(_env.WebRootPath, _opts.baseRoute, "index.html");
            if (File.Exists(indexInWwwroot))
            {
                // Try to open a file from wwwroot first
                using (var templateFile = File.OpenRead(indexInWwwroot))
                {
                    AssignPlaceholderValuesTo(templateFile).CopyTo(httpContext.Response.Body);
                }
            }
            else
            {
                // Fallback to Swashbuckle's embedded swagger ui
                AssignPlaceholderValuesTo(_swaggerAssembly.GetManifestResourceStream("Swashbuckle.SwaggerUi.CustomAssets.index.html"))
                    .CopyTo(httpContext.Response.Body);
            }
        }

        private bool RequestingSwaggerUi(HttpRequest request)
        {
            if (request.Method != "GET") return false;
            return _requestMatcher.TryMatch(request.Path, new RouteValueDictionary());
        }

        private Stream AssignPlaceholderValuesTo(Stream template)
        {
            var additionalQueryParamsJson = _opts.oauth2_additionalQueryStringParams != null ? 
                JsonConvert.SerializeObject(_opts.oauth2_additionalQueryStringParams) : "{}";

            var placeholderValues = new Dictionary<string, string>
            {
                { "%(SwaggerUrl)", _opts.definitionUrl },
                { "http://petstore.swagger.io/v2/swagger.json", _opts.definitionUrl },
                { "your-client-id", _opts.oauth2_clientId },
                { "your-app-name", _opts.oauth2_appName },
                { "your-realms", _opts.oauth2_realms },
                { "your-client-secret-if-required", _opts.oauth2_clientSecret },
                { "additionalQueryStringParams: {}", "additionalQueryStringParams: " + additionalQueryParamsJson }
            };

            var templateText = new StreamReader(template).ReadToEnd();
            var contentBuilder = new StringBuilder(templateText);
            foreach (var entry in placeholderValues)
            {
                contentBuilder.Replace(entry.Key, entry.Value);
            }

            return new MemoryStream(Encoding.UTF8.GetBytes(contentBuilder.ToString()));
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class CustomSwaggerMiddlewareExtensions
    {
        public static IApplicationBuilder UseCustomSwaggerUi(this IApplicationBuilder app,
            CustomSwaggerMiddlewareOpts opts)
        {
            var baseRoute = opts.baseRoute.Trim('/');
            app.UseMiddleware<CustomSwaggerMiddleware>(new object[] {
                opts
            });

            // Serve all other swagger-ui assets as static files
            var options = new FileServerOptions();
            options.RequestPath = "/" + baseRoute;
            options.EnableDefaultFiles = false;
            options.StaticFileOptions.ContentTypeProvider = new FileExtensionContentTypeProvider();
            options.FileProvider = new EmbeddedFileProvider(typeof(SwaggerUiBuilderExtensions).GetTypeInfo().Assembly,
                "Swashbuckle.SwaggerUi.bower_components.swagger_ui.dist");
            app.UseFileServer(options);
            return app;
        }
    }
}
