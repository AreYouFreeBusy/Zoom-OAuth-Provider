using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Zoom_OAuth_Demo.Startup))]
namespace Zoom_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
