using IdentityModel;
using IdentityServerWithAspNetIdentity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Claims;

namespace IdentityServerWithAspNetIdentity.Data
{
    public class ApplicationSeedData
    {
        public static void EnsureSeedData(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetService<ApplicationDbContext>();
                context.Database.Migrate();

                var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var jiangy = userMgr.FindByNameAsync("jiangy").Result;
                if (jiangy == null)
                {
                    jiangy = new ApplicationUser
                    {
                        UserName = "jiangy"
                    };
                    var result = userMgr.CreateAsync(jiangy, "Pass123$").Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    result = userMgr.AddClaimsAsync(jiangy, new Claim[]{
                        new Claim(JwtClaimTypes.Name, "jiangy Smith"),
                        new Claim(JwtClaimTypes.GivenName, "jiangy"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith"),
                        new Claim(JwtClaimTypes.Email, "jiangy@admin.com"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.WebSite, "http://jiangy.com"),
                        new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json)
                    }).Result;
                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }
                    Console.WriteLine("jiangy created");
                }
                else
                {
                    Console.WriteLine("jiangy already exists");
                }
            }
        }
    }
}
