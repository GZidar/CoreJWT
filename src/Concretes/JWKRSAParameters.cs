using CoreJWT.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CoreJWT.Concretes
{
    public class JWKRSAParameters : JsonWebBase, IJWKParameters
    {
        private byte[] _modulus { get; set; }
        private byte[] _firstPrime { get; set; }
        private byte[] _secondPrime { get; set; }
        private byte[] _exponent { get; set; }
        private byte[] _firstCRTExponent { get; set; }
        private byte[] _secondCRTExponent { get; set; }
        private byte[] _firstCRTCoefficient { get; set; }

        public string OtherPrimesInfo { get; set; }
        public string FirstPrime
        {
            get
            {
                return base64urlencode(_firstPrime);
            }

            set
            {
                _firstPrime = base64urldecode(value);
            }
        }

        public string SecondPrime
        {
            get
            {
                return base64urlencode(_secondPrime);
            }

            set
            {
                _secondPrime = base64urldecode(value);
            }
        }

        public string FirstCRTExponent
        {
            get
            {
                return base64urlencode(_firstCRTExponent);
            }

            set
            {
                _firstCRTExponent = base64urldecode(value);
            }
        }

        public string SecondCRTExponent
        {
            get
            {
                return base64urlencode(_secondCRTExponent);
            }

            set
            {
                _secondCRTExponent = base64urldecode(value);
            }
        }

        public string FirstCRTCoefficient
        {
            get
            {
                return base64urlencode(_firstCRTCoefficient);
            }

            set
            {
                _firstCRTCoefficient = base64urldecode(value);
            }
        }

        public string Modulus
        {
            get
            {
                return base64urlencode(_modulus);
            }

            set
            {
                _modulus = base64urldecode(value);
            }
        }

        public string Exponent
        {
            get
            {
                return base64urlencode(_exponent);
            }

            set
            {
                _exponent = base64urldecode(value);
            }
        }

        public string ToXml()
        {
            if (string.IsNullOrEmpty(Modulus))
                return string.Format("<RSAKeyValue><D>{0}</<D><P>{1}</P></RSAKeyValue>", Exponent, FirstPrime);
            else
                return string.Format("<RSAKeyValue><Modulus>{0}</<Modulus><Exponent>{1}</Exponent></RSAKeyValue>", Modulus, Exponent);
        }

        public string Encode(bool publicKey = true)
        {
            throw new NotImplementedException();
        }

        public RSAParameters ToRSA()
        {
            if (string.IsNullOrEmpty(Modulus))
            {
                return new RSAParameters
                {
                    D = _exponent,
                    P = _firstPrime,
                    Q = _secondPrime,
                    DP = _firstCRTExponent,
                    DQ = _secondCRTExponent,
                    InverseQ = _firstCRTCoefficient
                };
            }
            else
            {
                return new RSAParameters
                {
                    Modulus = _modulus,
                    Exponent = _exponent,
                };
            }
        }

        public string Serialize()
        {
            if (string.IsNullOrEmpty(Modulus))
                return string.Format(",\"d\":\"{0}\",\"p\":\"{1}\",\"q\":\"{2}\",\"dp\":\"{3}\",\"dq\":\"{4}\",\"qi\":\"{5}\",\"oth\":\"{6}\"",
                    Exponent, FirstPrime, SecondPrime, FirstCRTExponent, SecondCRTExponent, FirstCRTCoefficient, OtherPrimesInfo);
            else
                return string.Format(",\"e\":\"{0}\",\"n\":\"{1}\"", Exponent, Modulus);
        }
    }

}
