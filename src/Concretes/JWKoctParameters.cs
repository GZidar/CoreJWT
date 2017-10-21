using CoreJWT.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JWKoctParameters : JsonWebBase, IJWKParameters
    {
        private byte[] _keyValue { get; set; }

        public string KeyValue
        {
            get
            {
                return base64urlencode(_keyValue);
            }

            set
            {
                _keyValue = base64urldecode(value);
            }
        }

        public string ToXml()
        {
            throw new NotImplementedException();
        }

        public string Encode(bool publicKey = true)
        {
            throw new NotImplementedException();
        }

        public string Serialize()
        {
            return string.Format(",\"k\":\"{0}\"", KeyValue);
        }
    }

}
