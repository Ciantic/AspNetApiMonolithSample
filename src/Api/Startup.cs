using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AspNetApiMonolithSample.Models;
using AspNetApiMonolithSample.EntityFramework;
using AspNetApiMonolithSample.EntityFramework.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using AspNetApiMonolithSample.Mvc;
using AspNetApiMonolithSample.Stores;
using Swashbuckle.SwaggerGen.Generator;
using System.IO;
using OpenIddict;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using System;
using System.Diagnostics;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using System.Collections.Generic;

namespace AspNetApiMonolithSample
{
    public class Startup
    {
        private SqliteConnection inMemorySqliteConnection;

        public IConfigurationRoot Configuration { get; set; }

        private IHostingEnvironment env;

        public Startup(IHostingEnvironment env)
        {
            this.env = env;
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // Ordering matters, Identity first, then MvcCore and then Authorization
            services.AddCors();

            services.AddDbContext<AppDbContext>(options =>
            {
                if (env.IsDevelopment())
                {
                    inMemorySqliteConnection = new SqliteConnection("Data Source=:memory:");
                    inMemorySqliteConnection.Open();
                    options.UseSqlite(inMemorySqliteConnection);
                }
                else 
                {
                    options.UseSqlServer(Configuration.GetOrFail("Data:DefaultConnection:ConnectionString"));
                }
            });

            services.AddIdentity<User, Role>(opts => {
                //opts.Cookies.ApplicationCookieAuthenticationScheme
                opts.Cookies.ApplicationCookie.CookiePath = "/OpenId/";
            })
                .AddEntityFrameworkStores<AppDbContext, int>()
                .AddDefaultTokenProviders();

            services.AddOpenIddict<User, OpenIddictApplication<int>, OpenIddictAuthorization<OpenIddictToken<int>, int>, OpenIddictScope<int>, OpenIddictToken<int>, AppDbContext, int>()
                .SetAuthorizationEndpointPath("/connect/authorize")
                .SetLogoutEndpointPath("/connect/logout");

            services.AddMvcCore(opts =>
            {
                opts.Filters.Add(new ModelStateValidationFilter());
                opts.Filters.Add(new NullValidationFilter());
                opts.Filters.Add(new ApiExceptionFilter());
            })
                .AddApiExplorer()
                .AddAuthorization(opts => {
                    opts.AddPolicy("COOKIES", opts.DefaultPolicy);
                    opts.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
                        .RequireClaim(OpenIdConnectConstants.Claims.Scope, "api")
                        .Build();
                })
                .AddDataAnnotations()
                .AddFormatterMappings()
                .AddJsonFormatters();

            services.AddSwaggerGen(opts =>
            {
                if (Configuration.GetOrFail("Api:Url").EndsWith("/")) {
                    throw new System.Exception("Configuration `Api.Url` must not end with /");
                }
                
                opts.AddSecurityDefinition("oauth2", new OAuth2Scheme
                {
                    Type = "oauth2",
                    Flow = "implicit",
                    AuthorizationUrl = Configuration.GetOrFail("Api:Url") + "/OpenId/Authorize", 
                    TokenUrl = Configuration.GetOrFail("Api:Url") + "/OpenId/_token",
                    Scopes = new Dictionary<string, string>
                    {
                        { "api_user", "API user" }
                    }
                });
            });

            if (env.IsDevelopment())
            {
                services.AddTransient<IInitDatabase, AppDbInitDev>();
            }
            else
            {
                services.AddTransient<IInitDatabase, AppDbInitProd>();
            }
            
            services.AddTransient<IThingieStore, ThingieStore>();
            
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseStaticFiles();
            app.UseIdentity();
            
            if (env.IsDevelopment())
            {
                app.UseCors(builder =>
                {
                    builder.AllowAnyOrigin();
                });
            }

            app.UseOpenIddict();
            /*
            app.UseOpenIddictCore(builder =>
            {
                builder.Options.UseJwtTokens();

                if (env.IsDevelopment())
                {
                    builder.Options.AllowInsecureHttp = true;
                }
                
                builder.Options.ApplicationCanDisplayErrors = true;
                
                // ConfigurationEndpointPath and CryptographyEndpointPath has well-known uris, need not to be ovewritten
                builder.Options.AuthorizationEndpointPath = "/OpenId/Authorize"; 
                builder.Options.TokenEndpointPath = "/OpenId/_token";
                builder.Options.IntrospectionEndpointPath = "/OpenId/_introspection";
                // builder.Options.LogoutEndpointPath = "/OpenId/Logout";
                // builder.Options.UserinfoEndpointPath = Configuration["OpenIddict:UserinfoEndpointPath"];
            });
            */

            // use JWT bearer authentication
            app.UseJwtBearerAuthentication(new JwtBearerOptions()
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                RequireHttpsMetadata = false,
                Audience = Configuration.GetOrFail("Jwt:Audience"),
                Authority = Configuration.GetOrFail("Jwt:Authority"),
            });
            
            app.UseMvc();
            app.UseSwaggerGen("docs/{apiVersion}/definition.json");
            app.UseSwaggerUi("docs", "docs/definition.json");
            app.ApplicationServices.GetService<IInitDatabase>().InitAsync().Wait();
        }
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseKestrel()
                .UseStartup<Startup>()
                .Build();
            
            host.Run();
        }
    }
}