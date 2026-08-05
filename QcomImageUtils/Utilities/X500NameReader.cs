using System.Collections.Generic;
using System.Formats.Asn1;

namespace QcomImageUtils.Utilities;

internal static class X500NameReader
{
    public static IReadOnlyList<string> GetValues(byte[] encodedName, string oid)
    {
        var values = new List<string>();

        try
        {
            var reader = new AsnReader(encodedName, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            while (sequence.HasData)
            {
                AsnReader set = sequence.ReadSetOf(skipSortOrderValidation: true);
                while (set.HasData)
                {
                    ReadOnlyMemory<byte> encodedAttribute = set.ReadEncodedValue();
                    try
                    {
                        var attributeReader = new AsnReader(
                            encodedAttribute,
                            AsnEncodingRules.DER);
                        AsnReader attribute = attributeReader.ReadSequence();
                        string attributeOid = attribute.ReadObjectIdentifier();
                        string? value = TryReadDirectoryString(attribute);
                        if (attributeOid == oid && value is not null)
                            values.Add(value);
                    }
                    catch (AsnContentException)
                    {
                    }
                }
            }
        }
        catch (AsnContentException)
        {
            values.Clear();
        }

        return values;
    }

    private static string? TryReadDirectoryString(AsnReader reader)
    {
        if (!reader.HasData)
            return null;

        Asn1Tag tag = reader.PeekTag();
        if (tag.TagClass != TagClass.Universal)
        {
            reader.ReadEncodedValue();
            return null;
        }

        UniversalTagNumber tagNumber = (UniversalTagNumber)tag.TagValue;
        return tagNumber switch
        {
            UniversalTagNumber.UTF8String => reader.ReadCharacterString(UniversalTagNumber.UTF8String),
            UniversalTagNumber.PrintableString => reader.ReadCharacterString(UniversalTagNumber.PrintableString),
            UniversalTagNumber.TeletexString => reader.ReadCharacterString(UniversalTagNumber.TeletexString),
            UniversalTagNumber.IA5String => reader.ReadCharacterString(UniversalTagNumber.IA5String),
            UniversalTagNumber.BMPString => reader.ReadCharacterString(UniversalTagNumber.BMPString),
            _ => SkipValue(reader)
        };
    }

    private static string? SkipValue(AsnReader reader)
    {
        reader.ReadEncodedValue();
        return null;
    }
}
