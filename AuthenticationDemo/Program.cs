
var builder = WebApplication.CreateBuilder(args);
// Authentication Progression Plan (Simple to Advanced)
// 1	Basic Authentication	Custom-built or handler; username/password in header
// 2    Cookie Authentication	Login session stored in cookie; used in web apps
// 3    JWT (Bearer Token)	    Token-based; great for APIs and SPAs
// 4    Identity (with DB)	    ASP.NET Core Identity system + roles, password hashing
// 5    OAuth2 / OpenID (OIDC)	External providers like Google, Facebook, IdentityServer

// 1.Basic Authentication setup
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = "BasicAuth";
//    options.DefaultChallengeScheme = "BasicAuth";
//})
//.AddScheme<AuthenticationSchemeOptions, BasicAuthHandler>("BasicAuth", null);



// 2. Cookie Authentication setup
//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//    .AddCookie(options =>
//    {
//        options.LoginPath = "/login"; // Redirect to login page if not authenticated
//        options.AccessDeniedPath = "/access-denied"; // Redirect if access is denied
//        options.Cookie.Name = "MyAuthCookie";
//    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
// 1. Basic Authentication route example
//app.MapGet("/", () => "Public: no auth required.");
//app.MapGet("/secure", [Authorize] () => "Secure: You are authenticated!");



// 2. Cookie Authentication route example
//// Public route
//app.MapGet("/", () => "Welcome to the public homepage!");

//// Secure route (requires cookie)
//app.MapGet("/dashboard", [Authorize] (HttpContext context) =>
//{
//    var name = context.User.Identity?.Name;
//    return $"Welcome {name}, this is your dashboard!";
//});

//app.MapGet("/login", () =>
//{
//    return Results.Content("<form method='post' action='/login'>" +
//                           "<input type='text' name='username' placeholder='Username' required />" +
//                           "<input type='password' name='password' placeholder='Password' required />" +
//                           "<button type='submit'>Login</button>" +
//                           "</form>", "text/html");
//});

//// Login endpoint
//app.MapPost("/login", async (HttpContext context, string username, string password) =>
//{
//    if (username == "admin" && password == "password")
//    {
//        var claims = new List<Claim>
//        {
//            new Claim(ClaimTypes.Name, username),
//            new Claim(ClaimTypes.Role, "Admin")
//        };

//        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
//        var principal = new ClaimsPrincipal(identity);

//        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

//        return Results.Ok("Logged in successfully!");
//    }

//    return Results.Unauthorized();
//});

//// Logout
//app.MapPost("/logout", async (HttpContext context) =>
//{
//    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
//    return Results.Ok("Logged out successfully!");
//});

//// Access Denied page
//app.MapGet("/denied", () => Results.Problem("Access denied"));

app.Run();
