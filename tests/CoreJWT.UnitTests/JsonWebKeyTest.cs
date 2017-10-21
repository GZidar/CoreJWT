using CoreJWT.Concretes;
using CoreJWT.Enumerations;
using Xunit;

namespace CoreJWT.UnitTests
{
    [Trait("Category", "Unit Test")]
    public class JsonWebKeyTest : UnitTestBase
    {
        [Fact]
        public void SerializeAndDeserializeKey_OctType_ExpectSuccess()
        {
            // Arrange
            var jwk1 = new JsonWebKey
            {
                Type = JwaKeyType.oct,
                Id = "api.test.key",
                Usage = "sig",
                Parameters = new JWKoctParameters
                {
                    KeyValue = "dGVzdFNlY3JldA"
                }
            };

            // Act
            var key1 = jwk1.Serialize();

            var jwt2 = JsonWebKey.Deserialize(key1);

            var key2 = jwt2.Serialize();

            // Assert
            Assert.True(key1 == key2, "Keys do not match");
        }

        [Fact]
        public void ExportKeyAsXml_ExpectSuccess()
        {
            var jwk = "{\"kty\": \"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"api.test.key\",\"alg\":\"RS256\",\"n\":\"iqH76SE0-YxNl3cPdqErc_SLO57hq5bCNFUgQ0ZTOzhh2qP7PBrA0r8a9cUMA2fNp99mdaCixzm2bcdXvAfeGczRiLN6QiRJIdlV-V4CjaKTn-Br1_jx8TjFaZhgGxuTrxJ9aaNIYwTHn9Mu-Lhmr-kQn6gRTdhESxoJ1j4jN3YqXmRXaXgPQk2bGuuWpeKDNuFG1LodTIwgJLVurL1vZaYrMIsff3LFHv2S-r4iECMxs9OHGZct97Y6DYn2kcMag1V459C2PJDY20KAhRj4kCVpdDtUWADF0pgNeT3-QmMBradieBKIEP4CZtJpB0Ek8HZEf_PeqiFB4aRmc69JMw\"}";

            var key1 = JsonWebKey.Deserialize(jwk);
            var jwk1 = key1.Serialize();
            var xml = key1.ToXml();

             Assert.True(xml.Length > 0, "no xml created");
        }

        [Fact]
        public void SerializeAndDeserializeKey_RSAPublicType_ExpectSuccess()
        {
            // Arrange
            var jwk1 = new JsonWebKey
            {
                Type = JwaKeyType.RSA,
                Id = "api.test.key",
                Usage = "sig",
                Algorithm = JwaHashAlgorithm.RS256,
                Parameters = new JWKRSAParameters
                {
                    Exponent = "AQAB",
                    Modulus = "iqH76SE0-YxNl3cPdqErc_SLO57hq5bCNFUgQ0ZTOzhh2qP7PBrA0r8a9cUMA2fNp99mdaCixzm2bcdXvAfeGczRiLN6QiRJIdlV-V4CjaKTn-Br1_jx8TjFaZhgGxuTrxJ9aaNIYwTHn9Mu-Lhmr-kQn6gRTdhESxoJ1j4jN3YqXmRXaXgPQk2bGuuWpeKDNuFG1LodTIwgJLVurL1vZaYrMIsff3LFHv2S-r4iECMxs9OHGZct97Y6DYn2kcMag1V459C2PJDY20KAhRj4kCVpdDtUWADF0pgNeT3-QmMBradieBKIEP4CZtJpB0Ek8HZEf_PeqiFB4aRmc69JMw"
                }
            };

            // Act
            var key1 = jwk1.Serialize();

            var jwt2 = JsonWebKey.Deserialize(key1);

            var key2 = jwt2.Serialize();

            // Assert
            Assert.True(key1 == key2, "Keys do not match");
        }

        [Fact]
        public void SerializeAndDeserializeKey_ECPrivateType_ExpectSuccess()
        {
            // Arrange
            var jwk1 = new JsonWebKey
            {
                Type = JwaKeyType.EC,
                Id = "api.test.key",
                Usage = "sig",
                Algorithm = JwaHashAlgorithm.ES256,
                Parameters = new JWKECParameters
                {
                    KeyValue = "123456789"
                }
            };

            // Act
            var key1 = jwk1.Serialize();

            var jwt2 = JsonWebKey.Deserialize(key1);

            var key2 = jwt2.Serialize();

            // Assert
            Assert.True(key1 == key2, "Keys do not match");
        }
    }
}
