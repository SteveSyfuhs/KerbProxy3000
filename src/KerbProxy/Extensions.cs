using System.Collections.Generic;
using Titanium.Web.Proxy.EventArguments;

namespace KerbProxy
{
    public static class Extensions
    {
        public static T GetUserData<T>(this SessionEventArgsBase e, string name)
        {
            var userData = GetOrCreateUserData(e);

            if (!userData.TryGetValue(name, out object value))
            {
                return default(T);
            }

            return (T)value;
        }

        private static IDictionary<string, object> GetOrCreateUserData(SessionEventArgsBase e)
        {
            if (!(e.UserData is IDictionary<string, object> userData))
            {
                userData = new Dictionary<string, object>();

                e.UserData = userData;
            }

            return userData;
        }

        public static void SetUserData(this SessionEventArgsBase e, string name, object value)
        {
            var userData = GetOrCreateUserData(e);

            userData[name] = value;
        }
    }
}
