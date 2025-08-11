using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace AuthenticationDemo
{
    public class BasicAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public BasicAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock
        ) : base(options, logger, encoder, clock) { }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));

            try
            {
                var authHeader = Request.Headers.Authorization.ToString();
                if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(AuthenticateResult.Fail("Invalid Scheme"));

                var token = authHeader.Substring("Basic ".Length).Trim();
                var credentialBytes = Convert.FromBase64String(token);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');

                if (credentials.Length != 2)
                    return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));

                var username = credentials[0];
                var password = credentials[1];

                // Replace with DB or secure check
                if (username != "admin" || password != "password")
                    return Task.FromResult(AuthenticateResult.Fail("Invalid Username or Password"));

                var claims = new[] {
                    new Claim(ClaimTypes.Name, username)
                    };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return Task.FromResult(AuthenticateResult.Success(ticket));
            }
            catch
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
            }
        }
    }
}
