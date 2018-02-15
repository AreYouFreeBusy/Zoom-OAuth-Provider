//  Copyright 2017 Stefan Negritoiu. See LICENSE file for more information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Zoom
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the Zoom OAuth 2.0 middleware
    /// </summary>
    public class ZoomBeforeRedirectContext : BaseContext<ZoomAuthenticationOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The OWIN request context</param>
        /// <param name="options">The Zoom middleware options</param>
        public ZoomBeforeRedirectContext(IOwinContext context, ZoomAuthenticationOptions options)
            : base(context, options) 
        {
        }
    }
}
