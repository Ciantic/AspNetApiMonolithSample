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
using AspNetApiMonolithSample.Services;
using OpenIddict.Models;
using Swashbuckle.SwaggerGen.Generator;
using System.Collections.Generic;

namespace AspNetApiMonolithSample
{
    public class Startup
    {
        private SqliteConnection inMemorySqliteConnection;
        
        public IConfigurationRoot Configuration { get; set; }
        
        public Startup(IHostingEnvironment env) {
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }
        
        public void ConfigureServices(IServiceCollection services)
        {
            inMemorySqliteConnection = new SqliteConnection("Data Source=:memory:");
            inMemorySqliteConnection.Open();
            
            // Ordering matters, Identity first, then MvcCore and then Authorization
            
            services.AddCors();
            
            services.AddDbContext<AppDbContext>(options => {
                // options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]);
                options.UseSqlite(inMemorySqliteConnection);
            });
            
            services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<AppDbContext, int>()
                .AddDefaultTokenProviders()
                .AddOpenIddictCore<Application<int>>(c => {
                    c.UseEntityFramework();
                });
                
            services.AddMvcCore(opts => {
                    opts.Filters.Add(new ModelStateValidationFilter());
                    opts.Filters.Add(new NullValidationFilter());
                    opts.Filters.Add(new ApiExceptionFilter());
                })
                .AddApiExplorer()
                .AddAuthorization()
                .AddDataAnnotations()
                .AddFormatterMappings()
                .AddJsonFormatters();
                
            services.AddSwaggerGen(opts => {
                opts.AddSecurityDefinition("oauth2", new OAuth2Scheme
                {
                    Type = "oauth2",
                    Flow = "password",
                    TokenUrl = "http://localhost:5000/connect/token"
                    /*,
                    Scopes = new Dictionary<string, string>
                        {
                            { "offline_access", "offline access" }//,
                            //{ "write", "write access" }
                        }
                    */
                });
            });

            // TODO: IF DEV ENV:
            services.AddTransient<IInitDatabase, AppDbInitDev>();
            // services.AddTransient<IInitDatabase, AppDbInitProd>();
            services.AddTransient<UserService>();
            services.AddTransient<IThingieStore, ThingieStore>();
        }
        

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            
            if (env.IsDevelopment()) {
                app.UseCors(builder => {
                    builder.AllowAnyOrigin();
                });
            }
            
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseOpenIddictCore(builder =>
            {
                // tell openiddict you're wanting to use jwt tokens
                builder.Options.UseJwtTokens();
                // NOTE: for dev consumption only! for live, this is not encouraged!
                builder.Options.AllowInsecureHttp = true;
                builder.Options.ApplicationCanDisplayErrors = true;
            });
 
            // use jwt bearer authentication
            app.UseJwtBearerAuthentication(new JwtBearerOptions() {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                RequireHttpsMetadata = false,
                Audience = "http://localhost:5000/",
                Authority = "http://localhost:5000/",
            }); 
            
            app.UseMvc();
            app.UseSwaggerGen();
            app.UseSwaggerUi();
            app.ApplicationServices.GetService<IInitDatabase>().InitAsync().Wait();
        }
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}