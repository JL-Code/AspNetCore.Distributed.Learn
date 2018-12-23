using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using IdentityServerWithAspNetIdentity.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using IdentityServerWithAspNetIdentity.Models;
using IdentityServerWithAspNetIdentity.Entities;
using IdentityServer4.Services;

namespace IdentityServerWithAspNetIdentity
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connstr = Configuration.GetConnectionString("DefaultConnection");
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connstr));

            //services.AddDefaultIdentity<IdentityUser>()
            //    .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            //.AddDefaultUI();

            // Add application services.
            //services.AddTransient<IEmailSender, EmailSender>();

            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_1);

            // configure identity server with in-memory stores, keys, clients and scopes
            // 使用内存存储，密钥，客户端和范围配置身份服务器
            services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
            .AddDeveloperSigningCredential()
            .AddInMemoryPersistedGrants()
            //.AddInMemoryIdentityResources(Config.GetIdentityResources())
            //.AddInMemoryApiResources(Config.GetApiResources())
            //.AddInMemoryClients(Config.GetClients())
            // 使用EF 代替内存存储
            // 存储配置信息 Client Resource 
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = builder =>
                {
                    builder.UseSqlServer(connstr, sql =>
                    {
                        sql.MigrationsAssembly(typeof(Startup).Assembly.GetName().Name);
                    });
                };
            })
            // 存储授权操作
             .AddOperationalStore(options =>
              {
                  options.ConfigureDbContext = builder =>
                  {
                      builder.UseSqlServer(connstr, sql =>
                      {
                          sql.MigrationsAssembly(typeof(Startup).Assembly.GetName().Name);
                      });
                  };
              })
            .AddAspNetIdentity<ApplicationUser>()
            .Services.AddScoped<IProfileService, ProfileService>();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");

            }

            app.UseStaticFiles();

            //app.UseAuthentication();
            // not needed, since UseIdentityServer adds the authentication middleware 不需要，因为UseIdentityServer添加了身份验证中间件
            app.UseIdentityServer();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
