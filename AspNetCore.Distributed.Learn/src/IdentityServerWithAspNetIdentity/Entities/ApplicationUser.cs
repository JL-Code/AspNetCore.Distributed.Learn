using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerWithAspNetIdentity.Entities
{
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// 头像
        /// </summary>
        public string Avatar { get; set; }
    }
}
