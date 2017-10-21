using CoreJWT.Enumerations;
using CoreJWT.Interfaces;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JsonWebKey : JsonWebBase
    {
        public JwaKeyType @Type { get; set; } = JwaKeyType.oct;
        public string Usage { get; set; }
        public string Id { get; set; }
        public IJWKParameters Parameters { get; set; }
        public JwaHashAlgorithm? Algorithm { get; set; }

        public string ToXml()
        {
            return Parameters.ToXml();
        }

        public string Encode(bool publicKey = true)
        {
            var result = Parameters.Encode(publicKey);

            return result;
        }

        public string Decode(string jwt)
        {
            var result = Encoding.UTF8.GetString(base64urldecode(jwt));
            return result;
        }

        public string Serialize()
        {
            var result = string.Format("{{\"kty\":\"{0}\"", Type);

            if (!string.IsNullOrEmpty(Usage))
                result += string.Format(",\"use\":\"{0}\"", Usage);

            if (!string.IsNullOrEmpty(Id))
                result += string.Format(",\"kid\":\"{0}\"", Id);

            if (Algorithm != null)
                result += string.Format(",\"alg\":\"{0}\"", Algorithm);

            if (Parameters != null)
                result += Parameters.Serialize();

            result += "}";

            return result;
        }

        public static JsonWebKey Deserialize(string jwk)
        {
            var result = new JsonWebKey();

            var process = (JObject)JsonConvert.DeserializeObject(jwk);
            JToken outValue;
            process.TryGetValue("kty", out outValue);
            if (outValue != null)
            {
                if (outValue.Value<string>() == JwaKeyType.oct.ToString())
                {
                    result.Type = JwaKeyType.oct;
                    result.Parameters = new JWKoctParameters();

                    process.TryGetValue("k", out outValue);
                    if (outValue != null)
                        ((JWKoctParameters)result.Parameters).KeyValue = outValue.Value<string>();
                }
                else if (outValue.Value<string>() == JwaKeyType.EC.ToString())
                {
                    result.Type = JwaKeyType.EC;
                    var parameters = new JWKECParameters();

                    process.TryGetValue("d", out outValue);
                    if (outValue != null)
                    {
                        parameters.KeyValue = outValue.Value<string>();

                    }
                    else
                    {
                        process.TryGetValue("crv", out outValue);
                        if (outValue != null)
                            parameters.Curve = outValue.Value<string>();

                        process.TryGetValue("x", out outValue);
                        if (outValue != null)
                            parameters.XCoordinate = outValue.Value<string>();

                        process.TryGetValue("y", out outValue);
                        if (outValue != null)
                            parameters.YCoordinate = outValue.Value<string>();

                        result.Parameters = parameters;
                    }

                    result.Parameters = parameters;
                }
                else if (outValue.Value<string>() == JwaKeyType.RSA.ToString())
                {
                    result.Type = JwaKeyType.RSA;
                    var parameters = new JWKRSAParameters();

                    process.TryGetValue("e", out outValue);
                    if (outValue != null)
                    {
                        parameters.Exponent = outValue.Value<string>();

                        process.TryGetValue("n", out outValue);
                        if (outValue != null)
                            parameters.Modulus = outValue.Value<string>();

                    }
                    else
                    {
                        process.TryGetValue("d", out outValue);
                        if (outValue != null)
                            parameters.Exponent = outValue.Value<string>();

                        process.TryGetValue("p", out outValue);
                        if (outValue != null)
                            parameters.FirstPrime = outValue.Value<string>();

                        process.TryGetValue("q", out outValue);
                        if (outValue != null)
                            parameters.SecondPrime = outValue.Value<string>();

                        process.TryGetValue("dp", out outValue);
                        if (outValue != null)
                            parameters.FirstCRTExponent = outValue.Value<string>();

                        process.TryGetValue("dq", out outValue);
                        if (outValue != null)
                            parameters.SecondCRTExponent = outValue.Value<string>();

                        process.TryGetValue("qi", out outValue);
                        if (outValue != null)
                            parameters.FirstCRTCoefficient = outValue.Value<string>();

                        process.TryGetValue("oth", out outValue);
                        if (outValue != null)
                            parameters.OtherPrimesInfo = outValue.Value<string>();

                        result.Parameters = parameters;
                    }

                    result.Parameters = parameters;
                }
            }

            process.TryGetValue("use", out outValue);
            if (outValue != null)
                result.Usage = outValue.Value<string>();

            process.TryGetValue("kid", out outValue);
            if (outValue != null)
                result.Id = outValue.Value<string>();

            process.TryGetValue("alg", out outValue);
            if (outValue != null)
            {
                if (outValue.Value<string>() == JwaHashAlgorithm.HS256.ToString())
                    result.Algorithm = JwaHashAlgorithm.HS256;
                else if (outValue.Value<string>() == JwaHashAlgorithm.RS256.ToString())
                    result.Algorithm = JwaHashAlgorithm.RS256;
                else if (outValue.Value<string>() == JwaHashAlgorithm.ES256.ToString())
                    result.Algorithm = JwaHashAlgorithm.ES256;
            }

            return result;
        }
    }
}
