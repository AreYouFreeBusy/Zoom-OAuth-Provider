//  Copyright 2017 Stefan Negritoiu (FreeBusy). See LICENSE file for more information.

using System;

namespace Owin.Security.Providers.Zoom
{
    public static class ZoomAuthenticationExtensions
    {
        public static IAppBuilder UseZoomAuthentication(this IAppBuilder app, ZoomAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(ZoomAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseZoomAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseZoomAuthentication(new ZoomAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}