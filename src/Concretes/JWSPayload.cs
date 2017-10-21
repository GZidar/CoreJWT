using CoreJWT.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JWSPayload
    {
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public string Audience { get; set; }
        public DateTime? ExpirationTime { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? IssuedAt { get; set; }
        public string ID { get; set; }

        public Dictionary<string, dynamic> ClaimsSet { get; set; } = new Dictionary<string, dynamic>();

        public string Serialize()
        {
            var tempClaims = new Dictionary<string, dynamic>(ClaimsSet);

            if (!string.IsNullOrEmpty(Issuer))
                tempClaims.Add("iss", Issuer);
            if (!string.IsNullOrEmpty(Subject))
                tempClaims.Add("sub", Subject);
            if (!string.IsNullOrEmpty(ID))
                tempClaims.Add("jti", ID);
            if (!string.IsNullOrEmpty(Audience))
                tempClaims.Add("aud", Audience);
            if (ExpirationTime != null)
                tempClaims.Add("exp", ExpirationTime.Value.Encode());
            if (NotBefore != null)
                tempClaims.Add("nbf", NotBefore.Value.Encode());
            if (IssuedAt != null)
                tempClaims.Add("iat", IssuedAt.Value.Encode());

            return JsonConvert.SerializeObject(tempClaims);
        }

        public static JWSPayload Deserialize(string json)
        {
            var result = new JWSPayload();

            try
            {
                var process = (JObject)JsonConvert.DeserializeObject(json);
                foreach (JToken child in process.Children())
                {
                    var key = ((JProperty)child).Name;
                    var value = ((JProperty)child).Value;

                    switch (key)
                    {
                        case "iss":
                            {
                                result.Issuer = (string)value;
                                break;
                            }
                        case "sub":
                            {
                                result.Subject = (string)value;
                                break;
                            }
                        case "jti":
                            {
                                result.ID = (string)value;
                                break;
                            }
                        case "aud":
                            {
                                result.Audience = (string)value;
                                break;
                            }
                        case "exp":
                            {
                                result.ExpirationTime = ((int)value).Decode();
                                break;
                            }
                        case "nbf":
                            {
                                result.NotBefore = ((int)value).Decode();
                                break;
                            }
                        case "iat":
                            {
                                result.IssuedAt = ((int)value).Decode();
                                break;
                            }
                        default:
                            {
                                result.ClaimsSet.Add(key, value);
                                break;
                            }
                    }

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
