using System.Text;

namespace DotNetCertAuthSample.Services;

public static class DerEncoding
{
    /// <summary>
    /// PrintableString: https://msdn.microsoft.com/en-us/library/windows/desktop/bb540812%28v=vs.85%29.aspx
    /// </summary>
    public static byte[] EncodePrintableString(string data)
    {
        var dataBytes = Encoding.ASCII.GetBytes(data);

        return getDerBytes(0x13, dataBytes);
    }

    /// <summary>
    /// Integer: https://msdn.microsoft.com/en-us/library/windows/desktop/bb540806%28v=vs.85%29.aspx
    /// </summary>
    public static byte[] EncodeInteger(int data)
    {
        if (data > byte.MaxValue)
        {
            throw new NotSupportedException(
                "Support for integers greater than 255 not yet implemented."
            );
        }

        var dataBytes = new byte[] { (byte)data };
        return getDerBytes(0x02, dataBytes);
    }

    /// <summary>
    /// Octet: https://msdn.microsoft.com/en-us/library/windows/desktop/bb648644%28v=vs.85%29.aspx
    /// </summary>
    public static byte[] EncodeOctet(byte[] data)
    {
        return getDerBytes(0x04, data);
    }

    private static byte[] getDerBytes(int tag, byte[] data)
    {
        if (data.Length > byte.MaxValue)
        {
            throw new NotSupportedException(
                "Support for integers greater than 255 not yet implemented."
            );
        }

        var header = new byte[] { (byte)tag, (byte)data.Length };
        return header.Concat(data).ToArray();
    }
}
