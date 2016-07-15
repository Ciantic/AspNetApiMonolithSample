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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict;
using Swashbuckle.Swagger.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api
{
    /// <summary>
    /// Snippets of HTML to inject to the various pages, purpose is to provide branding
    /// through external snippets of HTML/CSS/JavaScript instead writing it in the API.
    /// </summary>
    public class UiBrandingHtml
    {
        /// <summary>
        /// Login page
        /// </summary>
        public string Login { get; set; } = "";

        /// <summary>
        /// OpenId authorize form (Accept or Deny)
        /// </summary>
        public string Authorize { get; set; } = "";

        /// <summary>
        /// Generic error page, e.g. 404
        /// </summary>
        public string Error { get; set; } = "";

        /// <summary>
        /// Two Factor authentication form
        /// </summary>
        public string TwoFactor { get; set; } = "";
    }

    /// <summary>
    /// Front end urls which user is redirected to deal with various parts of the 
    /// application.
    /// </summary>
    public class FrontendUrls
    {
        /// <summary>
        /// When user resets their password they will be emailed this link to reset the password
        /// </summary>
        public string ResetPassword { get; set; } = "";

        /// <summary>
        /// When user registers they are emailed this confirmation link
        /// </summary>
        public string RegisterConfirmEmail { get; set; } = "";
    }
    
    /// <summary>
    /// Startup class for Asp Net Core
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Development time Sqlite connection
        /// </summary>
        private SqliteConnection inMemorySqliteConnection;

        private readonly IConfigurationRoot Configuration;

        private readonly IHostingEnvironment env;

        /// <summary>
        /// Create a startup class, never created manually. This is initiated by UseStartup 
        /// of the WebHostBuilder.
        /// </summary>
        /// <param name="env"></param>
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
                return Task.CompletedTask;
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Groups actions in Swagger UI and in generated SDK e.g.
        /// 
        /// "SomeApp.Controllers.HomeController" becomes "Home"
        /// "SomeApp.Controllers.Something.OtherController" becomes "Something.Other"
        /// </summary>
        public static string groupActions(ApiDescription s)
        { 
            var r = new Regex(@"Controllers.(.*?)Controller");
            var m = r.Match(s.ActionDescriptor.DisplayName);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
            return null;
        }

        /// <summary>
        /// Asp Net Core's dependency injection configuration
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors();

            // Add database in the application
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

            // Register MVC specific services, such as JSON, Authorization, ...
            services.AddMvcCore(opts =>
            {
                opts.Filters.Add(new ModelStateValidationFilter());
                opts.Filters.Add(new NullValidationFilter());
                opts.Filters.Add(new ApiErrorFilter());
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
                    OnRedirectToAccessDenied = redirectOnlyOpenId,
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
                opts.GroupActionsBy(groupActions);

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

            // Stores and repositories
            services.AddScoped<IThingieStore, ThingieStore>();

            services.AddTransient<EmailService, EmailService>();
            services.Configure<EmailPlaceholders>(Configuration.GetSection("EmailPlaceholders"));
            services.AddSingleton<IEmailSender>((s) =>
            {
                return new EmailSender(s)
                {
                    FromName = Configuration.GetValue<string>("EmailSender:FromName"),
                    FromEmail = Configuration.GetValue<string>("EmailSender:FromEmail"),
                    SmtpHost = Configuration.GetValue<string>("EmailSender:SmtpHost"),
                    SmtpPort = Configuration.GetValue<int>("EmailSender:SmtpPort"),
                    SmtpSsl = Configuration.GetValue<bool>("EmailSender:SmtpSsl", true),
                    SmtpUsername = Configuration.GetValue<string>("EmailSender:SmtpUsername"),
                    SmtpPassword = Configuration.GetValue<string>("EmailSender:SmtpPassword"),
                };
            });

            services.Configure<Dictionary<string, OpenIddictApplication>>(Configuration.GetSection("Applications"));
            services.Configure<UiBrandingHtml>(Configuration.GetSection("UiBrandingHtml"));
            services.Configure<FrontendUrls>(Configuration.GetSection("FrontendUrls"));

            if (env.IsDevelopment())
            {
                services.AddTransient<IInitDatabase, AppDbInitDev>();
            }
            else
            {
                services.AddTransient<IInitDatabase, AppDbInitProd>();
            }
        }

        /// <summary>
        /// Asp Net Core's application configuration
        /// </summary>
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                loggerFactory.AddConsole(LogLevel.Debug);
            } else
            {
                loggerFactory.AddConsole(LogLevel.Warning);
            }

            app.UseStaticFiles();

            // use JWT bearer authentication
            app.UseJwtBearerAuthentication(new JwtBearerOptions()
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                RequireHttpsMetadata = false,
                Audience = Configuration.GetOrFail("Jwt:Audience"),
                Authority = Configuration.GetOrFail("Jwt:Authority"),
            });

            app.UseIdentity();
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseCors(builder =>
                {
                    builder.AllowAnyOrigin();
                });
            }

            app.UseStatusCodePagesWithReExecute("/Error", "?status={0}");

            app.UseOpenIddict();
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
                Console.Write("> ");
                string command = (Console.ReadLine() ?? "").Trim().ToLower();
                switch (command)
                {
                    case "mails":
                        {
                            Console.WriteLine("List of mails:");
                            var appDbContextOpts = services.GetService<DbContextOptions<AppDbContext>>();
                            using (var appDbContext = new AppDbContext(appDbContextOpts)) { 
                                var mails = await appDbContext.Emails.ToListAsync();
                                foreach (var m in mails)
                                {
                                    Console.WriteLine($"* To: {m.ToEmail} ({m.ProcessGuid})");
                                    Console.WriteLine($"Subject: {m.Subject} ");
                                    Console.WriteLine($"Message:\r\n\r\n{m.Body}\r\n\r\n");
                                }
                            }
                            Console.WriteLine("End of mails.");
                            break;
                        }
                    default:
                        {
                            Console.WriteLine($"'{command}' is not recognized command.");
                            break;
                        }
                }
            }
        }

        /// <summary>
        /// Main entry point of the application
        /// </summary>
        /// <param name="args">
        ///     <list type="bullet">
        ///         <item>
        ///             <term>gensdk</term>
        ///             <description>Will output a API.ts SDK for TypeScript.</description>
        ///         </item>
        ///         <item>
        ///             <term>dev</term>
        ///             <description>When in Development environment will start additionally interactive console.</description>
        ///         </item>
        ///     </list>
        /// </param>
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseKestrel()
                .UseStartup<Startup>()
                .Build();

            var env = host.Services.GetService(typeof(IHostingEnvironment)) as IHostingEnvironment;

            if (new List<string>(args).Contains("gensdk"))
            {
                Console.WriteLine("Generating the SDK...");
                var mvcOptions = host.Services.GetService<IOptions<MvcJsonOptions>>();
                var apiProvider = host.Services.GetService<IApiDescriptionGroupCollectionProvider>();
                var logger = host.Services.GetService<Logger<GenSdk>>();
                var wrote = new GenSdk(apiProvider, mvcOptions, logger).Generate(new GenSdkOptions()
                {
                    GroupActionsBy = groupActions,
                });

                if (wrote)
                {
                    Console.WriteLine("Generation done, file Api.ts was written.");
                } else
                {
                    Console.WriteLine("Generation done, no changes.");
                }
                return;
            }

            if (env.IsDevelopment())
            {
                if (new List<string>(args).Contains("dev")) {
                    Task.Run(() =>
                    {
                        DevelopmentInteractive(host.Services).Wait();
                    });
                }
                host.Run();
            }
            else
            {
                host.Run();
            }
        }
    }
}