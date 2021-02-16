using CoreJWT.Concretes;
using CoreJWT.Enumerations;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace CoreJWT.UnitTests
{
    [Trait("Category", "Unit Test")]
    public class JsonWebTokenTest : UnitTestBase
    {
        [Fact]
        public void SerializeToken_WithExternalKey_ExpectSuccess()
        {
            // Arrange
            var jwt = new JsonWebToken();

            jwt.Payload.ClaimsSet.Add("iss", "joe");
            jwt.Payload.ClaimsSet.Add("exp", 1300819380);
            jwt.Payload.ClaimsSet.Add("http://example.com/is_root", true);

            // Act
            var result = jwt.Encode("testSecret").Split('.');

            // Assert
            Assert.Equal(3, result.Length);
            Assert.Equal("eyJhbGciOiJIUzI1NiJ9", result[0]);
            Assert.Equal("eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", result[1]);
            Assert.Equal("skz3lnLKEPkw6UdL_GRvF0nEk0Lkjgi7RxEErtsMKfo", result[2]);
        }

        [Fact]
        public void SerializeToken_WithEmbeddedKey_ExpectSuccess()
        {
            // Arrange
            var jwt = new JsonWebToken();

            jwt.Header.Key = new JsonWebKey
            {
                Type = JwaKeyType.oct,
                Parameters = new JWKoctParameters
                {
                    KeyValue = "dGVzdFNlY3JldA"
                }
            };

            jwt.Payload.ClaimsSet.Add("iss", "joe");
            jwt.Payload.ClaimsSet.Add("exp", 1300819380);
            jwt.Payload.ClaimsSet.Add("http://example.com/is_root", true);

            // Act
            var result = jwt.Encode().Split('.');

            // Assert
            Assert.Equal(3, result.Length);
            Assert.Equal("eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiZEdWemRGTmxZM0psZEEifX0", result[0]);
            Assert.Equal("eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", result[1]);
            Assert.Equal("dFbvZ81nypLEWlKsCu13ZvtJY1he1m13CbQDSmlD4XE", result[2]);
        }

        [Fact]
        public void DeserializeToken_WithExternalKey_ExpectSuccess()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + 
                        "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "uYvH3ZD1ch6AFw5WE2Bt0vVxsyz_VlSPlAysTzzSNxY";

            // Act
            var result = JsonWebToken.Decode(token, "testSecret");

            // Assert
            Assert.Single(result.Payload.ClaimsSet);
            Assert.Equal(new DateTime(2011, 3, 22, 18, 43, 0), result.Payload.ExpirationTime);
            Assert.Equal("joe", result.Payload.Issuer);
            Assert.Equal("JWT", result.Header.Type);
            Assert.Equal(JwaHashAlgorithm.HS256, result.Header.Algorithm);
        }

        [Fact]
        public void DeserializeToken_WithIncorrectKey_ExpectError()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                        "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "uYvH3ZD1ch6AFw5WE2Bt0vVxsyz_VlSPlAysTzzSNxY";

            // Act & Assert
            Assert.Throws<Exception>(() => { JsonWebToken.Decode(token, "wrongSecret"); });
        }

        [Fact]
        public void DeserializeToken_WithIncorrectPayload_ExpectError()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                        "eyJpc3MiOiJqb2UleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "uYvH3ZD1ch6AFw5WE2Bt0vVxsyz_VlSPlAysTzzSNxY";

            // Act
            Assert.Throws<Exception>(() => { JsonWebToken.Decode(token, "testSecret"); });
        }

        [Fact]
        public void DeserializeToken_WithIncorrectHeader_ExpectError()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1JhbGciOiJIUzI1NiJ9." +
                        "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "uYvH3ZD1ch6AFw5WE2Bt0vVxsyz_VlSPlAysTzzSNxY";

            // Act & Assert
            Assert.Throws<Exception>(() => { JsonWebToken.Decode(token, "testSecret"); });
        }

        [Fact]
        public void DeserializeToken_WithIncorrectSignature_ExpectError()
        {
            // Arrange
            var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                        "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "uYvH3ZD1ch6AFwsdfWE2Bt0vVxsyz_VlSPlAysTzzSNxY";

            // Act & Assert
            Assert.Throws<Exception>(() => { JsonWebToken.Decode(token, "testSecret"); });
        }

        [Fact]
        public void DeserializeToken_WithEmbeddedKey_ExpectSuccess()
        {
            // Arrange
            var token = "eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJvY3QiLCJrIjoiZEdWemRGTmxZM0psZEEifX0." +
                        "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                        "dFbvZ81nypLEWlKsCu13ZvtJY1he1m13CbQDSmlD4XE";

            // Act
            var result = JsonWebToken.Decode(token);

            // Assert
            Assert.Single(result.Payload.ClaimsSet);
            Assert.Equal(new DateTime(2011,3,22,18,43,0), result.Payload.ExpirationTime);
            Assert.Equal("joe", result.Payload.Issuer);
            Assert.Equal("JWT", result.Header.Type);
            Assert.Equal("dGVzdFNlY3JldA", ((JWKoctParameters)result.Header.Key.Parameters).KeyValue);
            Assert.Equal(JwaHashAlgorithm.HS256, result.Header.Algorithm);
        }

        [Fact]
        public void SerializeAndDeserializeToken_ExpectSuccess()
        {
            // Arrange
            var jwt1 = new JsonWebToken();

            jwt1.Header.Key = new JsonWebKey
            {
                Type = JwaKeyType.oct,
                Parameters = new JWKoctParameters
                {
                    KeyValue = "dGVzdFNlY3JldA"
                }
            };

            jwt1.Payload.Issuer = "joe";
            jwt1.Payload.ExpirationTime = new DateTime(2017, 04, 09, 10, 15, 25);
            jwt1.Payload.ClaimsSet.Add("http://example.com/is_root", true);

            // Act
            var token1 = jwt1.Encode(); 

            var jwt2 = JsonWebToken.Decode(token1);

            var token2 = jwt2.Encode();

            // Assert
            Assert.True(token1 == token2, "Tokens do not match");
        }

    }
}
