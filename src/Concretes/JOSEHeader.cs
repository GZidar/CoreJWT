using CoreJWT.Enumerations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace CoreJWT.Concretes
{
    public class JOSEHeader
    {
        public string @Type { get; set; } = "JWT";
        public Uri KeyUri { get; set; }
        public JsonWebKey Key { get; set; }
        public JwaHashAlgorithm Algorithm { get; set; } = JwaHashAlgorithm.HS256;

        public string Serialize()
        {
            var result = "{";

            // Type parameter is optional - so leave it out if it is the default
            if (Type != "JWT")
                result += "\"typ\":\"" + Type + "\",";

            result += "\"alg\":\"" + Algorithm + "\"";

            // if a key location is specified then add it to the header
            if (!string.IsNullOrEmpty(KeyUri?.AbsoluteUri))
                result += ",\"jku\":\"" + KeyUri.AbsoluteUri + "\"";

            // if an actual key is specified then add it to the header
            if (Key != null)
                result += ",\"jwk\":" + Key.Serialize();

            result += "}";

            return result;
        }

        public static JOSEHeader Deserialize(string json)
        {
            var result = new JOSEHeader();

            try
            {
                var process = (JObject)JsonConvert.DeserializeObject(json);
                JToken outValue;
                process.TryGetValue("typ", out outValue);
                if (outValue != null)
                    result.Type = outValue.Value<string>();

                process.TryGetValue("alg", out outValue);
                if (outValue.Value<string>() == JwaHashAlgorithm.HS256.ToString())
                    result.Algorithm = JwaHashAlgorithm.HS256;
                else if (outValue.Value<string>() == JwaHashAlgorithm.RS256.ToString())
                    result.Algorithm = JwaHashAlgorithm.RS256;
                else if (outValue.Value<string>() == JwaHashAlgorithm.ES256.ToString())
                    result.Algorithm = JwaHashAlgorithm.ES256;

                process.TryGetValue("jku", out outValue);
                if (outValue != null)
                    result.KeyUri = new Uri(outValue.Value<string>());

                process.TryGetValue("jwk", out outValue);
                if (outValue != null)
                {
                    result.Key = JsonWebKey.Deserialize(outValue.ToString());
                }
            }
            catch
            {
                // no matter what error is raised this means that
                // the token is not ok so throw the invalid error
                throw new Exception("Token is invalid!");
            }

            return result;
        }
    }

}
