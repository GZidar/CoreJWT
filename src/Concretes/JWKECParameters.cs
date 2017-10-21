using CoreJWT.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JWKECParameters : IJWKParameters
    {
        public string Curve { get; set; }
        public string XCoordinate { get; set; }
        public string YCoordinate { get; set; }
        public string KeyValue { get; set; }

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
            if (string.IsNullOrEmpty("KeyValue"))
                return string.Format(",\"crv\":\"{0}\",\"x\":\"{1}\",\"y\":\"{2}\"", Curve, XCoordinate, YCoordinate);
            else
                return string.Format(",\"d\":\"{0}\"", KeyValue);
        }
    }
}
