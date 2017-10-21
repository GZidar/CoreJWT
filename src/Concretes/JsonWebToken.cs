using CoreJWT.Enumerations;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JsonWebToken : JsonWebBase
    {
        public JOSEHeader Header { get; set; } = new JOSEHeader();
        public JWSPayload Payload { get; set; } = new JWSPayload();
        public string Signature { get; set; } = "";

        public bool Verify()
        {
            return true;
        }

        public string Encode(string secret = null, JsonWebKey jwk = null)
        {
            var result = "";

            var header = base64urlencode(Encoding.UTF8.GetBytes(Header.Serialize()));
            var payload = base64urlencode(Encoding.UTF8.GetBytes(Payload.Serialize()));
            var signingBytes = Encoding.UTF8.GetBytes(header + "." + payload);

            Signature = createSignature(signingBytes, Header, secret, jwk);

            result += header + "." + payload + "." + Signature;

            return result;
        }

        public static JsonWebToken Decode(string token, string secret = null, JsonWebKey jwk = null, bool doNotSign = false)
        {
            var result = new JsonWebToken();

            try
            {
                var parts = token.Split('.');

                var header = Encoding.UTF8.GetString(base64urldecode(parts[0]));

                result.Header = JOSEHeader.Deserialize(header);

                if (!doNotSign)
                {
                    var signingBytes = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
                    var signature = createSignature(signingBytes, result.Header, secret, jwk, parts[2]);

                    // compare the signature calculated to the one supplied and if they are different
                    // reject the token as invalid
                    if (signature != parts[2])
                        throw new Exception("Token is invalid!");

                    result.Signature = signature;
                }

                var payload = Encoding.UTF8.GetString(base64urldecode(parts[1]));

                result.Payload = JWSPayload.Deserialize(payload);
            }
            catch
            {
                throw;
            }

            return result;
        }

        private static string createSignature(byte[] signingBytes, JOSEHeader header, string secret = null, JsonWebKey jwk = null, string signature = null)
        {
            var result = "";

            switch (header.Algorithm)
            {
                case JwaHashAlgorithm.HS256:
                    {
                        var algorithm = new HMACSHA256();
                        if (!string.IsNullOrEmpty(header.KeyUri?.AbsoluteUri))
                        {
                            // todo: write code here that will go off and get the key from the
                            // location specified by the Uri
                        }
                        else if (header.Key != null)
                        {
                            var keyValue = new byte[0];

                            if (header.Key.Type == JwaKeyType.oct)
                            {
                                keyValue = base64urldecode(((JWKoctParameters)header.Key.Parameters).KeyValue);
                            }

                            algorithm.Key = keyValue;
                        }
                        else
                        {
                            algorithm.Key = Encoding.UTF8.GetBytes(secret);
                        }

                        result = base64urlencode(algorithm.ComputeHash(signingBytes));
                        break;
                    }
                case JwaHashAlgorithm.RS256:
                    {
                        using (var algorithm = RSA.Create())
                        {
                            algorithm.ImportParameters(((JWKRSAParameters)jwk.Parameters).ToRSA());

                            if (string.IsNullOrEmpty(signature))
                            {
                                // todo: this means that we are creating a new signature so this needs to be calculated using a private key
                            }
                            else
                            {
                                // this means we are decoding an existing token and need to validate that the signature matches the key
                                if (algorithm.VerifyData(signingBytes, base64urldecode(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                                {
                                    result = signature;
                                }
                                else
                                {
                                    throw new Exception("Token is invalid!");
                                }
                            }
                        }

                        break;
                    }

            }

            return result;
        }
    }

}
