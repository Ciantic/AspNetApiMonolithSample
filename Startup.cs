using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using AspNetApiMonolithSample.Models;
using AspNetApiMonolithSample.EntityFramework;
using AspNetApiMonolithSample.EntityFramework.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;
using System.IO;
using Microsoft.Data.Sqlite;
using AspNetApiMonolithSample.Mvc;
using AspNetApiMonolithSample.Stores;
using AspNetApiMonolithSample.Services;

namespace AspNetApiMonolithSample
{
    public class Startup
    {
        private SqliteConnection inMemorySqliteConnection;
        
        public IConfigurationRoot Configuration { get; set; }
        
        public Startup(IHostingEnvironment env) {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }
        
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvcCore(opts => {
                    opts.Filters.Add(new ModelStateValidationFilter());
                    opts.Filters.Add(new NullValidationFilter());
                    opts.Filters.Add(new ApiExceptionFilter());
                })
                .AddDataAnnotations()
                .AddJsonFormatters();

            inMemorySqliteConnection = new SqliteConnection("Data Source=:memory:");
            inMemorySqliteConnection.Open();
            
            services.AddDbContext<AppDbContext>(options => {
                // options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]);
                options.UseSqlite(inMemorySqliteConnection);
            });

            services.AddIdentity<User, Role>(options => {
                options.Cookies.ApplicationCookie.AuthenticationScheme = "ApplicationCookie";
                options.Cookies.ApplicationCookie.CookieName = "AspNetApiMonolithSample";
            })
                .AddEntityFrameworkStores<AppDbContext, int>()
                .AddDefaultTokenProviders();
                
            // TODO: IF DEV ENV:
            services.AddTransient<IInitDatabase, AppDbInitDev>();
            // services.AddTransient<IInitDatabase, AppDbInitProd>();
            
            services.AddTransient<UserService>();
            services.AddTransient<IThingieStore, ThingieStore>();
        }
        

        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Debug);
            app.UseMvcWithDefaultRoute();
            app.UseIdentity();
            app.ApplicationServices.GetService<IInitDatabase>().Init();
        }
        public static void Main(string[] args)
        {
            var host = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseDefaultHostingConfiguration(args)
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}