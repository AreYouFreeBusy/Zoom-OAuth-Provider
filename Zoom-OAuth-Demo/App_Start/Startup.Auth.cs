using System;
using System.Configuration;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.Zoom;
using Zoom_OAuth_Demo.Models;

namespace Zoom_OAuth_Demo
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            var zoomOptions = new ZoomAuthenticationOptions {
                ClientId = "",
                ClientSecret = "",
                Provider = new ZoomAuthenticationProvider 
                {
                    OnAuthenticated = context => 
                    {
                        if (!String.IsNullOrEmpty(context.AccessToken)) 
                        {
                            // do something with AccessToken
                        }
                        if (!String.IsNullOrEmpty(context.RefreshToken)) 
                        {
                            // do something with RefreshToken
                        }
                        if (!String.IsNullOrEmpty(context.UserId))
                        {
                            // do something with UserId
                        }
                        if (!String.IsNullOrEmpty(context.AccountId)) 
                        {
                            // do something with AccountId
                        }
                        if (!String.IsNullOrEmpty(context.GivenName)) 
                        {
                            // do something with first name
                        }
                        if (!String.IsNullOrEmpty(context.Surname)) 
                        {
                            // do something with last name
                        }
                        return Task.FromResult<object>(null);
                    }
                }
            };
            zoomOptions.Scope.Add("user:read");
            zoomOptions.Scope.Add("meeting:write");
            zoomOptions.Scope.Add("recording:write");
            zoomOptions.Scope.Add("webinar:write");
            app.UseZoomAuthentication(zoomOptions);
        }
    }
}