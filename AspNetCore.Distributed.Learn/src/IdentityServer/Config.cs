using System;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;

namespace IdentityServer
{
    /// <summary>
    /// IdentityServer配置帮助类
    /// </summary>
    public static class Config
    {
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                // other clients omitted...

                // OpenID Connect implicit flow client (MVC)
                new Client
                {
                    ClientId = "mvc",
                    ClientName = "MVC Client",

                    AllowedGrantTypes = GrantTypes.Implicit,

                    // where to redirect to after login
                    RedirectUris = {"http://localhost:5001/signin-oidc"},

                    // where to redirect to after logout
                    PostLogoutRedirectUris = {"http://localhost:5001/signout-callback-oidc"},

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                    }
                }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile()
            };
        }

        public static List<TestUser> GetTestUsers()
        {
            return new List<TestUser>
            {
                new TestUser
                {
                    SubjectId = "001",
                    Username = "jiangy",
                    Password = "123456",
                    Claims = new []
                    {
                        new Claim("name", "蒋勇"),
                        new Claim("sex", "男"),
                        new Claim("website", "https://bob.com")
                    }
                }
            };
        }
    }
}