namespace SQLProxy.Tds;

internal static class TdsPacketType
{
    public const byte SqlBatch = 0x01;
    public const byte Rpc = 0x03;
    public const byte TabularResult = 0x04; // server -> client
    public const byte Attention = 0x06;
    public const byte TransactionManager = 0x0E;
    public const byte Login7 = 0x10;
    public const byte PreLogin = 0x12;
}

internal static class TdsStatus
{
    public const byte Normal = 0x00;
    public const byte EndOfMessage = 0x01;
    public const byte Ignore = 0x02;
    public const byte ResetConnection = 0x08;
}
