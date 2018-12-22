using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Collections.Generic;
using System.Security.Claims;

namespace AuthenticationService
{
    /**
     * 定义用户
     * 定义资源
     * 定义客户端
     */
    /// <summary>
    /// IdentityServer配置类
    /// </summary>
    public class IdentityServerConfig
    {
        // 定义用户

        public static ICollection<TestUser> GetUsers()
        {
            return new List<TestUser>
            {
                new TestUser{
                    SubjectId="001",//ID标识
                    Username="jiangy",
                     Claims= new List<Claim>{
                        new Claim("Role","Admin"),
                        new Claim("Sex","男")
                     },
                    IsActive = true,
                    Password ="123456"
                }
            };
        }

        // 定义客户端

        public static ICollection<Client> GetClients()
        {
            return new List<Client>
            {
                new Client{
                    RequireConsent=false,
                    ClientId ="mvc client",
                    ClientName="mvc 客户端",
                    ClientSecrets=new List<Secret>{
                      new Secret("secret".Sha256())
                    },
                    AllowedScopes = new List<string>{
                        "ApiResource001"
                    }
                }
            };
        }

        // 定义资源

        public static ICollection<ApiResource> GetApiResources()
        {
            return new List<ApiResource> {
                new ApiResource{
                    Name ="ApiResource001",
                    Description="Api资源测试001"
                }
            };
        }
    }
}
