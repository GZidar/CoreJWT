using System;

namespace CoreJWT.Extensions
{
    public static class JsonWebEncoding
    {
        public static int Encode(this DateTime source)
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return (int)source.Subtract(utc0).TotalSeconds;
        }

        public static DateTime Decode(this int source)
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            return utc0.AddSeconds(source);
        }
    }
}
