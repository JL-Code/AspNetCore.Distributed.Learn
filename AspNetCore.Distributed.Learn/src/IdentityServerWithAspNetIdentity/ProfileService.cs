using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServerWithAspNetIdentity.Entities;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServerWithAspNetIdentity
{
    public class ProfileService : IProfileService
    {

        private UserManager<ApplicationUser> _userManager;

        public ProfileService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        /// <summary>
        /// 获取用户描述信息
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type== "sub").Value;
            var user = await _userManager.FindByIdAsync(subjectId);

            context.IssuedClaims = await GetClaimsFromUserAsync(user);
        }

        private async Task<List<Claim>> GetClaimsFromUserAsync(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var claims = new List<Claim> {
               new Claim(JwtClaimTypes.Subject,user.Id),
               new Claim(JwtClaimTypes.PreferredUserName,user.UserName)
            };
            foreach (var claim in userClaims)
            {
                claims.Add(claim);
            }
            // 添加用户头像
            if (!string.IsNullOrWhiteSpace(user.Avatar))
            {
                claims.Add(new Claim("avatar", user.Avatar));
            }

            return claims;
        }

        /// <summary>
        /// 用户是否活跃
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task IsActiveAsync(IsActiveContext context)
        {
            // 默认为不活跃
            context.IsActive = false;

            var subjectId = context.Subject.Claims.FirstOrDefault(c => c.Type == "sub").Value;
            var user = await _userManager.FindByIdAsync(subjectId);

            context.IsActive = user != null;
        }
    }
}
