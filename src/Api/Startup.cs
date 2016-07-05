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
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using Swashbuckle.Swagger.Model;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AspNetApiMonolithSample
{
    public class BrandingHtml
    {
        public string Login { get; set; } = "";
        public string Authorize { get; set; } = "";
        public string Error { get; set; } = "";
        public string TwoFactor { get; set; } = "";
    }

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

        private static Task redirectOnlyOpenId(CookieRedirectContext ctx) {
            if (ctx.Request.Path.StartsWithSegments("/OpenId"))
            {
                ctx.Response.Redirect(ctx.RedirectUri);
            }
            return Task.FromResult(0);
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
                        .RequireClaim(OpenIdConnectConstants.Claims.Scope, "api_user")
                        .Build();
                })
                .AddDataAnnotations()
                .AddFormatterMappings()
                .AddJsonFormatters();


            services.AddIdentity<User, Role>(opts => {
                opts.Cookies.ApplicationCookie.Events = new CookieAuthenticationEvents()
                {
                    OnRedirectToLogin = redirectOnlyOpenId,
                    OnRedirectToAccessDenied = redirectOnlyOpenId
                };
                opts.Cookies.ApplicationCookie.AccessDeniedPath = "/OpenId/Login";
                opts.Cookies.ApplicationCookie.LoginPath = "/OpenId/Login";
                opts.Cookies.ApplicationCookie.LogoutPath = "/OpenId/Logout";
                opts.Cookies.ApplicationCookie.CookiePath = "/OpenId/";
            })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            var openIdDict = services.AddOpenIddict<User, AppDbContext>()
                .SetTokenEndpointPath("/OpenId/token")
                .SetAuthorizationEndpointPath("/OpenId/Authorize")
                .SetLogoutEndpointPath("/OpenId/Logout")
                .UseJsonWebTokens()
                .Configure(opts =>
                {
                    opts.ApplicationCanDisplayErrors = true;
                });

            if (env.IsDevelopment())
            {
                openIdDict.DisableHttpsRequirement();
            }

            services.AddSwaggerGen(opts =>
            {
                // Include .NET namespace in the Swagger UI sections
                opts.GroupActionsBy((s) =>
                {
                    var r = new Regex(@"Controllers.(.*?)Controller");
                    var m = r.Match(s.ActionDescriptor.DisplayName);
                    if (m.Success)
                    {
                        return m.Groups[1].Value;
                    }
                    return null;
                });

                if (Configuration.GetOrFail("Api:Url").EndsWith("/")) {
                    throw new System.Exception("Configuration `Api.Url` must not end with /");
                }
                
                opts.AddSecurityDefinition("oauth2", new OAuth2Scheme
                {
                    Type = "oauth2",
                    Flow = "implicit",
                    AuthorizationUrl = Configuration.GetOrFail("Api:Url") + "/OpenId/Authorize", 
                    TokenUrl = Configuration.GetOrFail("Api:Url") + "/OpenId/token",
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
            services.Configure<List<OpenIddictApplication>>(Configuration.GetSection("Applications"));
            services.Configure<BrandingHtml>(Configuration.GetSection("BrandingHtml"));
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
            app.UseSwagger("docs/{apiVersion}/definition.json");
            app.UseSwaggerUi("docs", "/docs/v1/definition.json");
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