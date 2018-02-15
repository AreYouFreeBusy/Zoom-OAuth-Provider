//  Copyright 2017 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Zoom
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class ZoomAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="ZoomAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Zoom access token</param>
        public ZoomAuthenticatedContext(
            IOwinContext context, string accessToken, string expires, string refreshToken, JObject userJson) 
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue)) 
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            UserId = userJson["id"]?.Value<string>();            
            Email = userJson["email"]?.Value<string>();
            GivenName = userJson["first_name"]?.Value<string>();
            Surname = userJson["last_name"]?.Value<string>();
            PersonalMeetingId = userJson["pmi"]?.Value<string>();
        }

        /// <summary>
        /// Gets the Zoom OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the scope for this Zoom OAuth access token
        /// </summary>
        public string[] Scope { get; private set; }

        /// <summary>
        /// Gets the Zoom access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; private set; }

        /// <summary>
        /// Gets the Zoom OAuth refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Zoom user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the email address
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the user's first name
        /// </summary>
        public string GivenName { get; private set; }
        
        /// <summary>
        /// Gets the user's last name
        /// </summary>
        public string Surname { get; private set; }

        /// <summary>
        /// Gets the Zoom user ID
        /// </summary>
        public string PersonalMeetingId { get; private set; }

        /// <summary>
        /// Gets the email address
        /// </summary>
        public string AccountType { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
