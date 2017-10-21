using System;
using System.Collections.Generic;
using System.Text;

namespace CoreJWT.Interfaces
{
    public interface IJWKParameters
    {
        string Serialize();
        string ToXml();
        string Encode(bool publicKey = true);
    }
}
