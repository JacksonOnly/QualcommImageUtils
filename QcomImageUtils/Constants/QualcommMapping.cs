using System.Collections.Generic;
using System.Collections.ObjectModel;
using QcomImageUtils.Types;

namespace QcomImageUtils.Constants;

/// <summary>
/// Provides immutable Qualcomm OEM and SoC identifier mappings.
/// </summary>
public static class QualcommMapping
{
    private static readonly Dictionary<uint, QualcommOemType> OemMappings =
        new Dictionary<uint, QualcommOemType>()
        {
            { 0x0000, QualcommOemType.Qualcomm },
            { 0x0001, QualcommOemType.Wingtech },
            { 0x0004, QualcommOemType.Zte },
            { 0x0011, QualcommOemType.Smartisan },
            { 0x0015, QualcommOemType.Huawei },
            { 0x0017, QualcommOemType.Lenovo },
            { 0x0020, QualcommOemType.Samsung },
            { 0x0029, QualcommOemType.Asus },
            { 0x0030, QualcommOemType.Haier },
            { 0x0031, QualcommOemType.Lg },
            { 0x0035, QualcommOemType.FoxconnNokia },
            { 0x42, QualcommOemType.Alcatel },
            { 0x45, QualcommOemType.Nokia },
            { 0x48, QualcommOemType.YuLong },
            { 0x51, QualcommOemType.OppoOneplusRealme },
            { 0x72, QualcommOemType.Xiaomi },
            { 0x73, QualcommOemType.Vivo },
            { 0x0130, QualcommOemType.GlocalMe },
            { 0x0139, QualcommOemType.Lyf },
            { 0x0168, QualcommOemType.Motorola },
            { 0x01B0, QualcommOemType.Motorola },
            { 0x0208, QualcommOemType.Motorola },
            { 0x0228, QualcommOemType.Motorola },
            { 0x2A96, QualcommOemType.Motorola },
            { 0x02E8, QualcommOemType.Lenovo },
            { 0x0328, QualcommOemType.Motorola },
            { 0x0368, QualcommOemType.Motorola },
            { 0x03C8, QualcommOemType.Motorola },
            { 0x00C8, QualcommOemType.Motorola },
            { 0x0348, QualcommOemType.Motorola },
            { 0x1043, QualcommOemType.Asus },
            { 0x1111, QualcommOemType.Asus },
            { 0x143A, QualcommOemType.Asus },
            { 0x1978, QualcommOemType.Blackphone },
            { 0x2A70, QualcommOemType.Oxygen },
            { 0x01A4, QualcommOemType.Honor },
            { 0x0144, QualcommOemType.BlackShark },
            { 0x013B, QualcommOemType.Qihoo360 },
            { 0x0138, QualcommOemType.Meizu },
            { 0x01E3, QualcommOemType.Meizu },
            { 0x01CF, QualcommOemType.Nothing },
            { 0x018C, QualcommOemType.Smartisan },
            { 0x0040, QualcommOemType.Lenovo },
            { 0x01C0, QualcommOemType.Huawei },
            { 0x01A3, QualcommOemType.Huawei },
            { 0x0180, QualcommOemType.Ontim },
            { 0x0160, QualcommOemType.Xtc },
            { 0x0038, QualcommOemType.Sharp},
            { 0x0636, QualcommOemType.Ontim},
            { 0x2016, QualcommOemType.Wingtech},
            { 0x0148, QualcommOemType.Meitu},
            { 0x0028, QualcommOemType.Motorola},
            { 0x6000, QualcommOemType.Lenovo},
            { 0x0149, QualcommOemType.Cloudminds},
            { 0x1520, QualcommOemType.Huaqin},
            { 0x1590, QualcommOemType.Huaqin},
            { 0x0043, QualcommOemType.Hisense},
            { 0x0090, QualcommOemType.Borqs},
        };
    private static readonly Dictionary<uint, QualcommSocType> SocHwVersionMappings =
        new Dictionary<uint, QualcommSocType>()
        {
            { 0x2013, QualcommSocType.Mdm9205 },
            { 0x2014, QualcommSocType.Qcs405 },
            { 0x2017, QualcommSocType.Ipq6018 },
            { 0x3002, QualcommSocType.Msm8998Sdm835 },
            { 0x3006, QualcommSocType.Sdm660 },
            { 0x3007, QualcommSocType.Sdm630 },
            { 0x4003, QualcommSocType.Qca4020 },
            { 0x4004, QualcommSocType.Qca6290 },
            { 0x400A, QualcommSocType.Qca6390 },
            { 0x400B, QualcommSocType.Qcn7605 },
            { 0x400D, QualcommSocType.Qcn9000 },
            { 0x4014, QualcommSocType.Moselle },
            { 0x4017, QualcommSocType.Wcn7850 },
            { 0x6000, QualcommSocType.Sdm845 },
            { 0x6001, QualcommSocType.Sda845 },
            { 0x6002, QualcommSocType.Sdx24 },
            { 0x6003, QualcommSocType.Sm8150 },
            { 0x6004, QualcommSocType.Sdm670 },
            { 0x6005, QualcommSocType.Sdm670 },
            { 0x6006, QualcommSocType.Sc8180X },
            { 0x6007, QualcommSocType.Sm6150 },
            { 0x6008, QualcommSocType.Sm8250 },
            { 0x600B, QualcommSocType.Sdx55Cd90Pg591 },
            { 0x600C, QualcommSocType.Sm7150 },
            { 0x600D, QualcommSocType.Sm7250Aa },
            { 0x600E, QualcommSocType.Sm7250Ab },
            { 0x600F, QualcommSocType.Sm8350 },
            { 0x6012, QualcommSocType.Sdm690 },
            { 0x6013, QualcommSocType.Chitwan },
            { 0x6014, QualcommSocType.Sc8280X },
            { 0x6016, QualcommSocType.OlympicV1 },
            { 0x6017, QualcommSocType.Cedros },
            { 0x6018, QualcommSocType.Sm7325 },
            { 0x7001, QualcommSocType.Qtang2 },
            { 0x7200, QualcommSocType.Sdm662 },
            { 0x9001, QualcommSocType.Sm6125 },
            { 0x9002, QualcommSocType.Sm4250Aa },
            { 0x9003, QualcommSocType.Agatti },
            { 0x9004, QualcommSocType.Sm4350 },
            { 0x9005, QualcommSocType.Sw5100 },
            { 0x9006, QualcommSocType.Sm6375 },
            { 0x9007, QualcommSocType.Sm6225 },
            { 0xA001, QualcommSocType.Sm8450 },
            { 0xA003, QualcommSocType.Sm8550Ab },
            { 0xA005, QualcommSocType.Sm7435Ab },
            { 0xA008, QualcommSocType.Sm8475 },
            { 0xA00C, QualcommSocType.Sm8650Ab },
            { 0xA012, QualcommSocType.Sm8750Ab },
            { 0xA013, QualcommSocType.Sm7675 },
            { 0xA018, QualcommSocType.Sm7635 },
            { 0xA01A, QualcommSocType.Sm8735 },
            { 0xA01B, QualcommSocType.Sm8845 },
        };
    private static readonly Dictionary<uint, QualcommSocType> SocMsmIdMappings =
        new Dictionary<uint, QualcommSocType>()
        {
            { 0x9440E1, QualcommSocType.Qdf2432 },
            { 0x9780E1, QualcommSocType.Ipq4018 },
            { 0x9790E1, QualcommSocType.Ipq4019 },
            { 0x0160E1, QualcommSocType.Qca4020 },
            { 0x9D00E1, QualcommSocType.Apq8076 },
            { 0x08A0E1, QualcommSocType.Apq807X },
            { 0x9000E1, QualcommSocType.Apq8084 },
            { 0x9010E1, QualcommSocType.Apq8084 },
            { 0x9630E1, QualcommSocType.Apq8092 },
            { 0x9410E1, QualcommSocType.Apq8094 },
            { 0x0940E1, QualcommSocType.Msm8905 },
            { 0x9600E1, QualcommSocType.Msm8909 },
            { 0x9680E1, QualcommSocType.Apq8009 },
            { 0x0510E1, QualcommSocType.Msm8909W },
            { 0x0520E1, QualcommSocType.Apq8009W },
            { 0x0960E1, QualcommSocType.Sdx24 },
            { 0x0970E1, QualcommSocType.Sdx24M },
            { 0x7050E1, QualcommSocType.Msm8916 },
            { 0x7060E1, QualcommSocType.Apq8016 },
            { 0x0560E1, QualcommSocType.Msm8917 },
            { 0x0860E1, QualcommSocType.Msm8920 },
            { 0x91B0E1, QualcommSocType.Msm8929 },
            { 0x04F0E1, QualcommSocType.Msm8937 },
            { 0x90B0E1, QualcommSocType.Msm8939 },
            { 0x90C0E1, QualcommSocType.Apq8036 },
            { 0x0500E1, QualcommSocType.Apq8037 },
            { 0x90D0E1, QualcommSocType.Apq8039 },
            { 0x9620E1, QualcommSocType.Msm8208 },
            { 0x06B0E1, QualcommSocType.Msm8940 },
            { 0x9720E1, QualcommSocType.Msm8952 },
            { 0x0460E1, QualcommSocType.Msm8953 },
            { 0x0660E1, QualcommSocType.Apq8053 },
            { 0x9900E1, QualcommSocType.Msm8976 },
            { 0x9690E1, QualcommSocType.Msm8992 },
            { 0x9400E1, QualcommSocType.Msm8994 },
            { 0x9470E1, QualcommSocType.Msm8996 },
            { 0x06F0E1, QualcommSocType.Msm8996Au },
            { 0x0630E1, QualcommSocType.Msm8996Au },
            { 0x05E0E1, QualcommSocType.Msm8998Sdm835 },
            { 0x94B0E1, QualcommSocType.Msm9055 },
            { 0x7F00E1, QualcommSocType.Mdm8225 },
            { 0x7F30E1, QualcommSocType.Mdm8225M },
            { 0x9730E1, QualcommSocType.Mdm9206Mdm9607Tx },
            { 0x9530E1, QualcommSocType.Mdm9245M },
            { 0x9200E1, QualcommSocType.Mdm9635 },
            { 0x04A0E1, QualcommSocType.Mdm9607 },
            { 0x9670E1, QualcommSocType.Mdm9609 },
            { 0x8090E1, QualcommSocType.Mdm9916 },
            { 0x80B0E1, QualcommSocType.Mdm9955 },
            { 0x9210E1, QualcommSocType.Mdm9X35 },
            { 0x9500E1, QualcommSocType.Mdm9X40 },
            { 0x9540E1, QualcommSocType.Mdm9X45 },
            { 0x03A0E1, QualcommSocType.Mdm9X50 },
            { 0x7F50E1, QualcommSocType.Mdm9X25 },
            { 0x7F40E1, QualcommSocType.Mdm9625 },
            { 0x7F10E1, QualcommSocType.Msm92251 },
            { 0x0320E1, QualcommSocType.Mdm9250 },
            { 0x0340E1, QualcommSocType.Mdm9255 },
            { 0x0390E1, QualcommSocType.Mdm9350 },
            { 0x03B0E1, QualcommSocType.Mdm9X55 },
            { 0x07D0E1, QualcommSocType.Mdm9X60 },
            { 0x07F0E1, QualcommSocType.Mdm9X65 },
            { 0x1280E1, QualcommSocType.Fsm100Xx },
            { 0x1650E1, QualcommSocType.Fsm10000 },
            { 0x1680E1, QualcommSocType.Fsm10005 },
            { 0x1690E1, QualcommSocType.Fsm10010 },
            { 0x16A0E1, QualcommSocType.Fsm10051 },
            { 0x16B0E1, QualcommSocType.Fsm10056 },
            { 0x1530E1, QualcommSocType.Ipq5018 },
            { 0x0C50E1, QualcommSocType.Sda439 },
            { 0x1610E1, QualcommSocType.OlympicV1 },
            { 0x1720E1, QualcommSocType.OlympicV1Hybrid },
            { 0x1060E1, QualcommSocType.Qm215 },
            { 0x0BE0E1, QualcommSocType.Sdm429 },
            { 0x0BF0E1, QualcommSocType.Sdm439 },
            { 0x09A0E1, QualcommSocType.Sdm450 },
            { 0x0AC0E1, QualcommSocType.Sdm630 },
            { 0x0BA0E1, QualcommSocType.Sdm632 },
            { 0x0BB0E1, QualcommSocType.Sda632 },
            { 0x08C0E1, QualcommSocType.Sdm660 },
            { 0x07B0E1, QualcommSocType.Sdx50M },
            { 0x0E50E1, QualcommSocType.Sdx55Cd90Pg591 },
            { 0x0CF0E1, QualcommSocType.Sdx55MCd90Ph809 },
            { 0x1250E1, QualcommSocType.Sa515M },
            { 0x0AB0E1, QualcommSocType.Qca6290 },
            { 0x0D90E1, QualcommSocType.Qca6390 },
            { 0x1310E1, QualcommSocType.Qca6480 },
            { 0x12E0E1, QualcommSocType.Qca6481 },
            { 0x12D0E1, QualcommSocType.Qca6491 },
            { 0x0D70E1, QualcommSocType.Qca6595 },
            { 0x0D30E1, QualcommSocType.Qcn7605 },
            { 0x0D50E1, QualcommSocType.Qcn7606 },
            { 0x0910E1, QualcommSocType.Sdm670 },
            { 0x0DB0E1, QualcommSocType.Sdm710 },
            { 0x0AA0E1, QualcommSocType.Qcs605 },
            { 0x0ED0E1, QualcommSocType.Sxr1120 },
            { 0x0EA0E1, QualcommSocType.Sxr1130 },
            { 0x08E0E1, QualcommSocType.Sda845 },
            { 0x1A60E1, QualcommSocType.Wcn7850 },
            { 0x1A70E1, QualcommSocType.Wcn7851 },
            { 0x1260E1, QualcommSocType.Ipq6018 },
            { 0x1070E1, QualcommSocType.Mdm9205 },
            { 0x1450E1, QualcommSocType.AgattiMdm },
            { 0x14F0E1, QualcommSocType.Agatti },
            { 0x1850E1, QualcommSocType.AgattiMdmIot },
            { 0x1860E1, QualcommSocType.Qcs2290 },
            { 0x13F0E1, QualcommSocType.Sdm690 },
            { 0x1410E1, QualcommSocType.BitraSda },
            { 0x1590E1, QualcommSocType.Cedros },
            { 0x1360E1, QualcommSocType.Sm4250Aa },
            { 0x1370E1, QualcommSocType.KamortaP },
            { 0x1730E1, QualcommSocType.KamortaIoTModem },
            { 0x1740E1, QualcommSocType.KamortaIoTApq },
            { 0x1C70E1, QualcommSocType.KamortaQrb },
            { 0x1B80E1, QualcommSocType.Sm6225 },
            { 0x1350E1, QualcommSocType.Sm8350 },
            { 0x1520E1, QualcommSocType.Sm8350 },
            { 0x19E0E1, QualcommSocType.Sm8350 },
            { 0x1A40E1, QualcommSocType.Vordonisi },
            { 0x1420E1, QualcommSocType.LahainaPremier },
            { 0x14A0E1, QualcommSocType.Sc8280X },
            { 0x14B0E1, QualcommSocType.Sa8295P },
            { 0x14C0E1, QualcommSocType.Sa8540P },
            { 0x16F0E1, QualcommSocType.Sm4350 },
            { 0x16E0E1, QualcommSocType.MannarP },
            { 0x1470E1, QualcommSocType.Moselle },
            { 0x10A0E1, QualcommSocType.Sm6125 },
            { 0x1750E1, QualcommSocType.NicobarIoTModem },
            { 0x1760E1, QualcommSocType.NicobarIoTApq },
            { 0x10B0E1, QualcommSocType.Qcn9000 },
            { 0x10C0E1, QualcommSocType.Qcn9001 },
            { 0x1150E1, QualcommSocType.Qcn9002 },
            { 0x10D0E1, QualcommSocType.Qcn9003 },
            { 0x10E0E1, QualcommSocType.Qcn9010 },
            { 0x10F0E1, QualcommSocType.Qcn9011 },
            { 0x1110E1, QualcommSocType.Qcn9012 },
            { 0x1140E1, QualcommSocType.Qcn9013 },
            { 0x0E30E1, QualcommSocType.Qcs401 },
            { 0x0E40E1, QualcommSocType.Qcs403 },
            { 0x1040E1, QualcommSocType.Qcs404 },
            { 0x0AF0E1, QualcommSocType.Qcs405 },
            { 0x0EB0E1, QualcommSocType.Qcs407 },
            { 0x0400E1, QualcommSocType.RennellCb },
            { 0x12A0E1, QualcommSocType.Rennell },
            { 0x12B0E1, QualcommSocType.RennellPremier },
            { 0x1490E1, QualcommSocType.RennellV11 },
            { 0x1630E1, QualcommSocType.Sd7250 },
            { 0x11E0E1, QualcommSocType.Sm7250Aa },
            { 0x1430E1, QualcommSocType.Sm7250Aa },
            { 0x0950E1, QualcommSocType.Sm6150 },
            { 0x0EC0E1, QualcommSocType.Sm6150P },
            { 0x0F50E1, QualcommSocType.Sm6155 },
            { 0x100EE0E1, QualcommSocType.Sm6155P },
            { 0x000EE0E1, QualcommSocType.Sa6155P },
            { 0x0011C0E1, QualcommSocType.Qcs610 },
            { 0x1011C0E1, QualcommSocType.Sm6150IoTHigh },
            { 0x001290E1, QualcommSocType.Sm6150IoTLow },
            { 0x0E60E1, QualcommSocType.Sm7150 },
            { 0x0A50E1, QualcommSocType.Sm8150 },
            { 0x0A60E1, QualcommSocType.Sm8150P },
            { 0x0CB0E1, QualcommSocType.Sdm855A },
            { 0x0C30E1, QualcommSocType.Sm8250Cd90Ph8051A },
            { 0x0CE0E1, QualcommSocType.Sm8250Cd90Ph8061A },
            { 0x0B80E1, QualcommSocType.Sc8180X },
            { 0x1230E1, QualcommSocType.Sa8189P },
            { 0x1560E1, QualcommSocType.Sm8250 },
            { 0x1510E1, QualcommSocType.Sa2150P },
            { 0x14D0E1, QualcommSocType.Sdm662 },
            { 0x18A0E1, QualcommSocType.Fraser },
            { 0x1920E1, QualcommSocType.Sm7325 },
            { 0x1930E1, QualcommSocType.Sc7280 },
            { 0x1940E1, QualcommSocType.Sc7295 },
            { 0x18B0E1, QualcommSocType.Qtang2 },
            { 0x12C0E1, QualcommSocType.Sc7180 },
            { 0x1A90E1, QualcommSocType.Sm6375 },
            { 0x0B70E1, QualcommSocType.Sdm850 },
            { 0x0E70E1, QualcommSocType.Sm7150P },
            { 0x0E80E1, QualcommSocType.Sa8155 },
            { 0x0E90E1, QualcommSocType.Sa8155P },
            { 0x1440E1, QualcommSocType.Chitwan },
            { 0x6220E1, QualcommSocType.Msm7227A },
            { 0x8040E1, QualcommSocType.Apq8026 },
            { 0x0550E1, QualcommSocType.Apq8017 },
            { 0x90F0E1, QualcommSocType.Apq8037 },
            { 0x9770E1, QualcommSocType.Apq8052 },
            { 0x9F00E1, QualcommSocType.Apq8056 },
            { 0x9120E1, QualcommSocType.Apq8062 },
            { 0x7190E1, QualcommSocType.Apq8064 },
            { 0x9300E1, QualcommSocType.Apq8092 },
            { 0x0640E1, QualcommSocType.Apq8096Sg },
            { 0x0620E1, QualcommSocType.Apq8098 },
            { 0x8110E1, QualcommSocType.Msm8210 },
            { 0x8140E1, QualcommSocType.Msm8212 },
            { 0x0590E1, QualcommSocType.Msm8217 },
            { 0x7BE0E1, QualcommSocType.Msm8274Aa },
            { 0x8120E1, QualcommSocType.Msm8610 },
            { 0x8160E1, QualcommSocType.Msm8112 },
            { 0x8170E1, QualcommSocType.Msm8510 },
            { 0x8100E1, QualcommSocType.Msm8110 },
            { 0x8080E1, QualcommSocType.Msm8512 },
            { 0x8150E1, QualcommSocType.Msm8612 },
            { 0x8010E1, QualcommSocType.Msm8626 },
            { 0x8050E1, QualcommSocType.Msm8926 },
            { 0x9180E1, QualcommSocType.Msm8928 },
            { 0x9170E1, QualcommSocType.Msm8628 },
            { 0x7210E1, QualcommSocType.Msm8930 },
            { 0x72C0E1, QualcommSocType.Msm8960 },
            { 0x9B00E1, QualcommSocType.Msm8956 },
            { 0x9100E1, QualcommSocType.Msm8962 },
            { 0x7B00E1, QualcommSocType.Msm8974 },
            { 0x7BD0E1, QualcommSocType.Msm8674Aa },
            { 0x7B30E1, QualcommSocType.Apq8074 },
            { 0x7B40E1, QualcommSocType.Msm8974Ab },
            { 0x7B80E1, QualcommSocType.Msm8974Pro },
            { 0x7BC0E1, QualcommSocType.Msm8974ABv3 },
            { 0x6B10E1, QualcommSocType.Msm8974Ac },
            { 0x05F0E1, QualcommSocType.Msm8996Pro },
            { 0x06C0E1, QualcommSocType.Msm8997 },
            { 0x0480E1, QualcommSocType.Mdm9207 },
            { 0x0CC0E1, QualcommSocType.Sdm636 },
            { 0x0930E1, QualcommSocType.Sda670 },
            { 0x08B0E1, QualcommSocType.Sdm845 },
            { 0x1970E1, QualcommSocType.Qcm6490 },
            { 0x1980E1, QualcommSocType.Qcs6490 },
            { 0x9820E1, QualcommSocType.Msm8976 },
            { 0x8060E1, QualcommSocType.Msm8326 },
            { 0x9640E1, QualcommSocType.Msm8992 },
            { 0x7B50E1, QualcommSocType.Msm8674Pro },
            { 0x80D0E1, QualcommSocType.Fsm9915 },
            { 0x9110E1, QualcommSocType.Msm8262 },
            { 0x0BC0E1, QualcommSocType.Sda630 },
            { 0x0F20E1, QualcommSocType.Sa4155P },
            { 0x0EF0E1, QualcommSocType.Sdm660 },
            { 0x8030E1, QualcommSocType.Msm8126 },
            { 0x9130E1, QualcommSocType.Apq8028 },
            { 0x0B90E1, QualcommSocType.Sda450 },
            { 0x05A0E1, QualcommSocType.Msm8617 },
            { 0x13D0E1, QualcommSocType.Qcm2150 },
            { 0x8020E1, QualcommSocType.Msm8526 },
            { 0x80A0E1, QualcommSocType.Fsm9965 },
            { 0x80F0E1, QualcommSocType.Fsm9900 },
            { 0x9140E1, QualcommSocType.Msm8128 },
            { 0x9160E1, QualcommSocType.Msm8528 },
            { 0x08F0E1, QualcommSocType.Sdm830 },
            { 0x09D0E1, QualcommSocType.Sda658 },
            { 0x08D0E1, QualcommSocType.Sdm658 },
            { 0x9830E1, QualcommSocType.Apq8076 },
            { 0x80C0E1, QualcommSocType.Fsm9950 },
            { 0x80E0E1, QualcommSocType.Fsm9910 },
            { 0x15A0E1, QualcommSocType.Qrb516 },
            { 0x8000E1, QualcommSocType.Msm8226 },
            { 0x9D70E1, QualcommSocType.Msm8229 },
            { 0x90E0E1, QualcommSocType.Msm8236 },
            { 0x9660E1, QualcommSocType.Mdm9309 },
            { 0x04E0E1, QualcommSocType.Apq8096Au },
            { 0x9570E1, QualcommSocType.Msm8239 },
            { 0x1990E1, QualcommSocType.OlympicLe },
            { 0x20F0E1, QualcommSocType.Unknown },
            { 0x7070E1, QualcommSocType.Unknown1 },
            { 0x0DA0E1, QualcommSocType.Sc8180Xp },
            { 0x60040000, QualcommSocType.Sdm670 },
            { 0x30060000, QualcommSocType.Sdm660 },
            { 0x60000000, QualcommSocType.Sdm845 },
            { 0x30020000, QualcommSocType.Msm8998Sdm835 },
        };

    /// <summary>
    /// Gets the read-only OEM identifier map.
    /// </summary>
    public static IReadOnlyDictionary<uint, QualcommOemType> OemMapping { get; } =
        new ReadOnlyDictionary<uint, QualcommOemType>(OemMappings);

    /// <summary>
    /// Gets the read-only SoC hardware-version map.
    /// </summary>
    public static IReadOnlyDictionary<uint, QualcommSocType> SocHwVerMapping { get; } =
        new ReadOnlyDictionary<uint, QualcommSocType>(SocHwVersionMappings);

    /// <summary>
    /// Gets the read-only MSM identifier map.
    /// </summary>
    public static IReadOnlyDictionary<uint, QualcommSocType> SocMsmIdMapping { get; } =
        new ReadOnlyDictionary<uint, QualcommSocType>(SocMsmIdMappings);

    /// <summary>
    /// Resolves an OEM identifier.
    /// </summary>
    /// <param name="oemId">The OEM identifier, or <see langword="null"/> when unavailable.</param>
    /// <returns>The matching OEM type, or <see cref="QualcommOemType.Unknown"/>.</returns>
    public static QualcommOemType GetOemType(uint? oemId) =>
        oemId is uint value && OemMappings.TryGetValue(value, out QualcommOemType oem)
            ? oem
            : QualcommOemType.Unknown;

    /// <summary>
    /// Tries to resolve a SoC from a hardware version or MSM identifier.
    /// </summary>
    /// <param name="socHwVersion">The full or family-level SoC hardware version.</param>
    /// <param name="msmId">The MSM identifier.</param>
    /// <param name="socType">Receives the resolved SoC type.</param>
    /// <returns><see langword="true"/> when a mapping is found; otherwise, <see langword="false"/>.</returns>
    public static bool TryGetSocType(
        uint? socHwVersion,
        uint? msmId,
        out QualcommSocType socType)
    {
        if (socHwVersion is uint hardwareVersion)
        {
            if (SocHwVersionMappings.TryGetValue(hardwareVersion, out socType))
                return true;

            uint family = hardwareVersion >> 16;
            if (family != 0 && SocHwVersionMappings.TryGetValue(family, out socType))
                return true;
        }

        if (msmId is uint msm && SocMsmIdMappings.TryGetValue(msm, out socType))
            return true;

        socType = QualcommSocType.Unknown;
        return false;
    }

    /// <summary>
    /// Resolves a SoC from a hardware version or MSM identifier.
    /// </summary>
    /// <param name="socHwVersion">The full or family-level SoC hardware version.</param>
    /// <param name="msmId">The MSM identifier.</param>
    /// <returns>The matching SoC type, or <see cref="QualcommSocType.Unknown"/>.</returns>
    public static QualcommSocType GetSocType(uint? socHwVersion, uint? msmId) =>
        TryGetSocType(socHwVersion, msmId, out QualcommSocType socType)
            ? socType
            : QualcommSocType.Unknown;

    /// <summary>
    /// Gets the display name for an OEM identifier.
    /// </summary>
    /// <param name="oemId">The OEM identifier.</param>
    /// <returns>The mapped enum name or a hexadecimal fallback name.</returns>
    public static string GetOemName(uint oemId) =>
        OemMappings.TryGetValue(oemId, out var name) ? name.ToString() : $"UnknownOem_{oemId:X4}";

    /// <summary>
    /// Gets the display name for a SoC hardware version.
    /// </summary>
    /// <param name="socId">The full or family-level SoC hardware version.</param>
    /// <returns>The mapped enum name or a hexadecimal fallback name.</returns>
    public static string GetSocNameByHwVer(uint socId) =>
        TryGetSocType(socId, null, out QualcommSocType socType)
            ? socType.ToString()
            : $"UnknownSocHwVer_{socId:X4}";

    /// <summary>
    /// Gets the display name for an MSM identifier.
    /// </summary>
    /// <param name="socId">The MSM identifier.</param>
    /// <returns>The mapped enum name or a hexadecimal fallback name.</returns>
    public static string GetSocNameByMsmId(uint socId) =>
        TryGetSocType(null, socId, out QualcommSocType socType)
            ? socType.ToString()
            : $"UnknownSocMsmId_{socId:X4}";
}
