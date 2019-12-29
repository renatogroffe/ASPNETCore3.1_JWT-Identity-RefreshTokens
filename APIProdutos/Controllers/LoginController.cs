using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using APIProdutos.Security;

namespace APIProdutos.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost]
        public object Post(
            [FromBody]AccessCredentials credenciais,
            [FromServices]AccessManager accessManager)
        {
            if (accessManager.ValidateCredentials(credenciais))
            {
                return accessManager.GenerateToken(credenciais);
            }
            else
            {
                return new
                {
                    Authenticated = false,
                    Message = "Falha ao autenticar"
                };
            }
        }
    }
}