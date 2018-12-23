using System.ComponentModel.DataAnnotations;

namespace IdentityServerWithAspNetIdentity.Controllers.Consent
{
    /// <summary>
    /// 登录输入模型
    /// </summary>
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
}