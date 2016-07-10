using AspNet.Security.OpenIdConnect.Extensions;
using AspNetApiMonolithSample.Api.EntityFramework;
using AspNetApiMonolithSample.Api.EntityFramework.Stores;
using AspNetApiMonolithSample.Api.Models;
using AspNetApiMonolithSample.Api.Mvc;
using AspNetApiMonolithSample.Api.Services;
using AspNetApiMonolithSample.Api.Stores;
using AspNetApiMonolithSample.Api.Swagger;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict;
using Swashbuckle.Swagger.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api
{
    public class OpenIdBrandingHtml
    {
        public string Login { get; set; } = "";
        public string Authorize { get; set; } = "";
        public string Error { get; set; } = "";
        public string TwoFactor { get; set; } = "";
    }
    
    public class Startup
    {
        private SqliteConnection inMemorySqliteConnection;

        private readonly IConfigurationRoot Configuration;

        private readonly IHostingEnvironment env;

        public Startup(IHostingEnvironment env)
        {
            this.env = env;
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        /// <summary>
        /// Use redirection for OpenId controllers
        /// 
        /// Includes the display property to inform login dialog 
        /// about the display type (e.g. page or popup).
        /// </summary>
        private static Task redirectOnlyOpenId(CookieRedirectContext ctx) {
            if (ctx.Request.Path.StartsWithSegments("/OpenId"))
            {
                var request = ctx.HttpContext.GetOpenIdConnectRequest();
                if (request != null && request.Display != null)
                {
                    ctx.Response.Redirect(QueryHelpers.AddQueryString(ctx.RedirectUri, new Dictionary<string, string>
                    {
                        { "display", request.Display }
                    }));
                } else
                {
                    ctx.Response.Redirect(ctx.RedirectUri);
                }
                
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
                    options.UseSqlServer(Configuration.GetConnectionString("Database"));
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
                .UseJsonWebTokens();

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

                if (!Configuration.GetOrFail("Api:Url").EndsWith("/")) {
                    throw new System.Exception("Configuration `Api.Url` must end with /");
                }
                
                opts.AddSecurityDefinition("oauth2", new OAuth2Scheme
                {
                    Type = "oauth2",
                    Flow = "implicit",
                    AuthorizationUrl = Configuration.GetOrFail("Api:Url") + "OpenId/Authorize", 
                    TokenUrl = Configuration.GetOrFail("Api:Url") + "OpenId/token",
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

            services.AddScoped<IThingieStore, ThingieStore>();
            services.AddTransient<EmailService, EmailService>();
            services.AddSingleton<IEmailSender>((s) =>
            {
                return new EmailSender(s)
                {
                    FromName = Configuration.GetValue<string>("EmailSender:FromName"),
                    FromEmail = Configuration.GetValue<string>("EmailSender:FromEmail"),
                    SmtpHost = Configuration.GetValue<string>("EmailSender:SmtpHost"),
                    SmtpPort = Configuration.GetValue<int>("EmailSender:SmtpPort"),
                    SmtpUsername = Configuration.GetValue<string>("EmailSender:SmtpUsername"),
                    SmtpPassword = Configuration.GetValue<string>("EmailSender:SmtpPassword"),
                };
            });

            services.Configure<Dictionary<string, OpenIddictApplication>>(Configuration.GetSection("Applications"));
            services.Configure<EmailPlaceholders>(Configuration.GetSection("EmailPlaceholders"));
            services.Configure<OpenIdBrandingHtml>(Configuration.GetSection("OpenIdBrandingHtml"));
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseStaticFiles();
            app.UseIdentity();
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
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
            app.UseCustomSwaggerUi(new CustomSwaggerMiddlewareOpts()
            {
                definitionUrl = "/docs/v1/definition.json",
                baseRoute = "docs",
                oauth2_clientId = Configuration.GetOrFail("Applications:Docs:ClientId"),
                oauth2_appName = Configuration.GetOrFail("Applications:Docs:DisplayName"),
                oauth2_clientSecret = Configuration.GetValue<string>("Applications:Docs:Secret"),
                oauth2_additionalQueryStringParams = new Dictionary<string, string>
                {
                    { "resource", Configuration.GetOrFail("Api:Url") }
                }
            });
            app.UseStatusCodePages();
            app.ApplicationServices.GetService<IInitDatabase>().InitAsync().Wait();
        }

        /// <summary>
        /// Experimental development interactive
        /// 
        /// Maybe removed in the future
        /// </summary>
        private static async Task DevelopmentInteractive(IServiceProvider services)
        { 
            while (true)
            {
                string command = (Console.ReadLine() ?? "").Trim().ToLower();
                switch (command)
                {
                    case "exit":
                        {
                            return;
                        }
                    case "mails":
                        {
                            var appDbContext = services.GetService(typeof(AppDbContext)) as AppDbContext;
                            var mails = await appDbContext.Emails.ToListAsync();
                            Console.WriteLine("List of mails:");
                            foreach (var m in mails)
                            {
                                Console.WriteLine($"* To: {m.ToEmail} Subject: {m.Subject} {m.ProcessGuid} {m.SentAt}");
                                Console.WriteLine($"* Message:\r\n\r\n{m.Body}\r\n\r\n");
                            }
                            Console.WriteLine("End of mails.");

                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Unregonized command");
                            break;
                        }
                }
            }
        }

        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseKestrel()
                .UseStartup<Startup>()
                .Build();

            var env = host.Services.GetService(typeof(IHostingEnvironment)) as IHostingEnvironment;
            if (env.IsDevelopment())
            {
                Task.Run(async () =>
                {
                    await DevelopmentInteractive(host.Services);
                });

                host.Run();
            }
            else
            {
                host.Run();
            }
        }
    }
}