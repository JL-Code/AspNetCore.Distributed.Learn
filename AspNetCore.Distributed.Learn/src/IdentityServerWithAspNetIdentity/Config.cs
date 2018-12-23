using System;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;

namespace IdentityServerWithAspNetIdentity
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
                //new Client
                //{
                //    ClientId = "mvc",
                //    ClientName = "MVC Client",

                //    AllowedGrantTypes = GrantTypes.Implicit,

                //    // where to redirect to after login
                //    RedirectUris = {"http://localhost:5001/signin-oidc"},

                //    // where to redirect to after logout
                //    PostLogoutRedirectUris = {"http://localhost:5001/signout-callback-oidc"},

                //    AllowedScopes = new List<string>
                //    {
                //        IdentityServerConstants.StandardScopes.OpenId,
                //        IdentityServerConstants.StandardScopes.Profile
                //    }
                //},

                // OpenID Connect hybrid flow and client credentials client (MVC)
                new Client
                {
                    ClientId = "hybrid_and_api_access_mvc",
                    ClientName = "混合流程验证客户端",
                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,

                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },

                    RedirectUris           = { "http://localhost:5001/signin-oidc" },
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-callback-oidc" },
                    RequireConsent =true,
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "api1"
                    },
                    AllowOfflineAccess = true
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

        public static IEnumerable<ApiResource> GetApiResources()
        {
            var apiResources = new List<ApiResource> {
                new ApiResource("api1","api1 测试服务")
            };
            return apiResources;
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