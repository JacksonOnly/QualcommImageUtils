using System.Buffers.Binary;
using System.Text;
using QcomImageUtils.Models;
using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class FirehoseCommandAnalyzerTests
{
    [Fact]
    public void TryAnalyze_PartialTableAndPackedPool_MergesCompleteCommandSet()
    {
        string[] commandNames =
        [
            "program", "read", "nop", "patch", "configure", "setbootablestoragedrive",
            "erase", "power", "quick_reset", "firmwarewrite", "getstorageinfo",
            "benchmark", "emmc", "ufs", "fixgpt", "getsha256digest"
        ];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCallingHandlerOnly: true);

        const int dataOffset = 0x400;
        const int entrySize = sizeof(ulong) * 2;
        WriteUInt64(image, dataOffset + entrySize * 4 + sizeof(ulong), 0);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands.Take(4),
            command => Assert.Equal(FirehoseCommandSource.CommandTable, command.Source));
        Assert.All(
            result.Commands.Skip(4),
            command => Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source));
    }

    [Fact]
    public void TryAnalyze_Arm64SupportedFunctionLoopHint_LimitsCommandTableToDeclaredCount()
    {
        string[] commandNames =
        [
            "program", "read", "nop", "patch", "configure", "erase", "power", "peek",
            "poke", "emmc", "ufs", "benchmark", "firmwarewrite", "getstorageinfo",
            "setbootablestoragedrive", "getsha256digest", "vendorcommand", "notadvertised"
        ];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);

        const ulong dataAddress = 0x200000;
        ulong supportedFunctionsAddress = dataAddress + 0x200UL;
        for (int index = 0; index < commandNames.Length; index++)
            supportedFunctionsAddress += checked((ulong)Encoding.ASCII.GetByteCount(commandNames[index]) + 1);

        const int codeOffset = 0x200;
        const ulong codeAddress = 0x100000;
        const ulong loggerAddress = codeAddress + 0x180;
        WriteUInt32(image, codeOffset + 0x00, EncodeArm64Adrp(codeAddress, supportedFunctionsAddress, 1));
        WriteUInt32(image, codeOffset + 0x04, EncodeArm64AddAddress(supportedFunctionsAddress, 1));
        WriteUInt32(image, codeOffset + 0x08, 0x52800222u); // MOV W2, #17
        WriteUInt32(image, codeOffset + 0x0C, 0x52800080u); // MOV W0, #4
        WriteUInt32(image, codeOffset + 0x10, EncodeArm64BranchLink(codeAddress + 0x10, loggerAddress));
        WriteUInt32(image, codeOffset + 0x14, EncodeArm64Adrp(codeAddress + 0x14, dataAddress, 21));
        WriteUInt32(image, codeOffset + 0x18, EncodeArm64AddAddress(dataAddress, 21));
        WriteUInt32(image, codeOffset + 0x1C, EncodeArm64Move(20, 31)); // MOV X20, XZR
        WriteUInt32(image, codeOffset + 0x20, EncodeArm64Branch(codeAddress + 0x20, codeAddress + 0x34));
        WriteUInt32(image, codeOffset + 0x24, 0xF84106A2u); // LDR X2, [X21], #16
        WriteUInt32(image, codeOffset + 0x28, 0x52800080u); // MOV W0, #4
        WriteUInt32(image, codeOffset + 0x2C, EncodeArm64BranchLink(codeAddress + 0x2C, loggerAddress));
        WriteUInt32(image, codeOffset + 0x30, 0x91000694u); // ADD X20, X20, #1
        WriteUInt32(image, codeOffset + 0x34, 0xF100469Fu); // CMP X20, #17
        WriteUInt32(
            image,
            codeOffset + 0x38,
            EncodeArm64ConditionalBranch(codeAddress + 0x38, codeAddress + 0x24, condition: 1));
        WriteUInt32(image, codeOffset + 0x3C, 0xD65F03C0u); // RET
        WriteUInt32(image, codeOffset + 0x180, 0xD65F03C0u); // logger RET

        int packedOffset = 0xA00;
        for (int index = 0; index < commandNames.Length; index++)
        {
            WriteAsciiAt(image, packedOffset, commandNames[index]);
            packedOffset += Encoding.ASCII.GetByteCount(commandNames[index]) + 1;
        }
        WriteAsciiAt(image, packedOffset, "Calling handler for %s");

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames.Take(17), result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "notadvertised");
        Assert.Equal(0x200000UL, result.Commands[0].TableEntryAddress);
        Assert.Equal(
            16UL,
            result.Commands[1].TableEntryAddress!.Value
            - result.Commands[0].TableEntryAddress!.Value);
    }

    [Fact]
    public void TryAnalyze_Arm64ExpiredHintEvidence_DoesNotCombineOldTableWithLateCount()
    {
        string[] commandNames =
        [
            "program", "read", "nop", "patch", "configure", "erase", "power", "peek",
            "poke", "emmc", "ufs", "benchmark", "firmwarewrite", "getstorageinfo",
            "setbootablestoragedrive", "getsha256digest", "vendorcommand", "notadvertised"
        ];
        byte[] image = ExpandElf64CodeSegment(
            CreateElf(
                is64Bit: true,
                prefixLength: 0,
                machine: 183,
                commands: commandNames,
                includeDispatchText: true,
                includeSigDiagnostic: false,
                extraStrings: []),
            codeSize: 0x800,
            dataOffset: 0x1000);

        const int codeOffset = 0x200;
        const ulong dataAddress = 0x200000;
        ulong supportedFunctionsAddress = dataAddress + 0x200UL;
        for (int index = 0; index < commandNames.Length; index++)
            supportedFunctionsAddress += checked((ulong)Encoding.ASCII.GetByteCount(commandNames[index]) + 1);

        WriteUInt32(image, codeOffset, 0x58003800u);     // LDR X0, [PC, #0x700]
        WriteUInt32(image, codeOffset + 0x04, 0x58003823u); // LDR X3, [PC, #0x704]
        WriteUInt32(image, codeOffset + 0x08, 0x91004063u); // ADD X3, X3, #16
        for (int offset = 0x0C; offset <= 0x600; offset += sizeof(uint))
            WriteUInt32(image, codeOffset + offset, 0xD503201Fu); // NOP
        WriteUInt32(image, codeOffset + 0x604, 0x52800221u); // MOV W1, #17
        WriteUInt32(image, codeOffset + 0x608, 0x7100445Fu); // CMP W2, #17
        WriteUInt32(image, codeOffset + 0x60C, 0xD65F03C0u); // RET
        WriteUInt64(image, codeOffset + 0x700, supportedFunctionsAddress);
        WriteUInt64(image, codeOffset + 0x708, dataAddress);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.Contains(result.Commands, command => command.Name == "notadvertised");
    }

    [Fact]
    public void TryAnalyze_Arm32SupportedFunctionLoopHint_LimitsCommandTableToDeclaredCount()
    {
        string[] commandNames =
        [
            "program", "read", "nop", "patch", "configure", "erase", "power", "peek",
            "poke", "emmc", "ufs", "benchmark", "firmwarewrite", "getstorageinfo",
            "setbootablestoragedrive", "getsha256digest", "vendorcommand", "notadvertised"
        ];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);

        const ulong dataAddress = 0x200000;
        ulong supportedFunctionsAddress = dataAddress + 0x200UL;
        for (int index = 0; index < commandNames.Length; index++)
            supportedFunctionsAddress += checked((ulong)Encoding.ASCII.GetByteCount(commandNames[index]) + 1);

        WriteUInt32(image, 0x200, 0xE59F0020u);         // LDR R0, [PC, #32]
        WriteUInt32(image, 0x204, 0xE3A01011u);         // MOV R1, #17
        WriteUInt32(image, 0x208, 0xE3520011u);         // CMP R2, #17
        WriteUInt32(image, 0x20C, 0xE59F3018u);         // LDR R3, [PC, #24]
        WriteUInt32(image, 0x210, 0xE2833008u);         // ADD R3, R3, #8
        WriteUInt32(image, 0x228, checked((uint)supportedFunctionsAddress));
        WriteUInt32(image, 0x22C, checked((uint)dataAddress));

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames.Take(17), result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "notadvertised");
        Assert.Equal(0x200000UL, result.Commands[0].TableEntryAddress);
    }

    [Fact]
    public void TryAnalyze_ThumbSupportedFunctionLoopHint_LimitsCommandTableToDeclaredCount()
    {
        const int declaredCommandCount = 7;
        string[] commandNames =
        [
            "program", "read", "nop", "patch", "configure", "erase", "vendorcommand",
            "notadvertised"
        ];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);

        const int codeOffset = 0x200;
        const ulong codeAddress = 0x100000;
        const ulong tableAddress = 0x200000;
        const int supportedFunctionsLiteralOffset = 0x20;
        const int tableLiteralOffset = 0x24;
        ulong supportedFunctionsAddress = tableAddress + 0x200UL;
        for (int index = 0; index < commandNames.Length; index++)
            supportedFunctionsAddress += checked((ulong)Encoding.ASCII.GetByteCount(commandNames[index]) + 1);

        WriteUInt32(image, 24, checked((uint)(codeAddress | 1UL)));
        WriteUInt16(
            image,
            codeOffset,
            EncodeThumbLiteralLoad(
                0,
                codeAddress,
                codeAddress + supportedFunctionsLiteralOffset));
        WriteUInt16(
            image,
            codeOffset + 0x02,
            checked((ushort)(0x2100u | declaredCommandCount))); // MOVS R1, #count
        WriteUInt16(
            image,
            codeOffset + 0x04,
            checked((ushort)(0x2A00u | declaredCommandCount))); // CMP R2, #count
        WriteUInt16(
            image,
            codeOffset + 0x06,
            EncodeThumbLiteralLoad(
                3,
                codeAddress + 0x06,
                codeAddress + tableLiteralOffset));
        WriteUInt16(image, codeOffset + 0x08, 0x4770); // BX LR
        WriteUInt32(
            image,
            codeOffset + supportedFunctionsLiteralOffset,
            checked((uint)supportedFunctionsAddress));
        WriteUInt32(image, codeOffset + tableLiteralOffset, checked((uint)tableAddress));

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(
            commandNames.Take(declaredCommandCount),
            result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "notadvertised");
        Assert.Equal(tableAddress, result.Commands[0].TableEntryAddress);
    }

    [Fact]
    public void TryAnalyze_Elf64TableAndAuthenticationTag_ReturnsTableAndInlineCommands()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: true,
            extraStrings: ["req", "emmc"]);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(5, result.Commands.Count);
        Assert.Equal(
            ["program", "read", "nop", "vendorcommand", "sig"],
            result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands.Take(4),
            command =>
            {
                Assert.Equal(FirehoseCommandSource.CommandTable, command.Source);
                Assert.NotNull(command.TableEntryAddress);
                Assert.NotNull(command.HandlerAddress);
            });
        FirehoseCommandInfo inline = result.Commands[4];
        Assert.Equal(FirehoseCommandSource.InlineDispatch, inline.Source);
        Assert.Null(inline.TableEntryAddress);
        Assert.Null(inline.HandlerAddress);
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
        Assert.DoesNotContain(result.Commands, command => command.Name == "emmc");
    }

    [Fact]
    public void TryAnalyze_Arm64TagDataFlowWithoutDiagnostic_ReturnsOnlyDispatchTag()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "req", "emmc"],
            includeInlineTagCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(
            ["program", "read", "nop", "vendorcommand", "sig"],
            result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
        Assert.DoesNotContain(result.Commands, command => command.Name == "emmc");
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[4].Source);
    }

    [Fact]
    public void TryAnalyze_Arm64ResolvedBlrTagGetter_ReturnsSig()
    {
        string[] tableCommands = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: tableCommands,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "emmc"],
            includeInlineTagCode: true,
            useArm64RegisterGetterCall: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal([.. tableCommands, "sig"], result.Commands.Select(command => command.Name));
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[^1].Source);
    }

    [Fact]
    public void TryAnalyze_Arm64GetterReturnValueOverwritten_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "emmc"],
            includeInlineTagCode: true);
        WriteUInt32(image, 0x200 + 0xCC, EncodeArm64Move(0, 9));
        WriteUInt32(image, 0x200 + 0xD0, 0xD65F03C0u); // RET
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
    }

    [Fact]
    public void TryAnalyze_Arm32TagDataFlowWithoutDiagnostic_ReturnsOnlyDispatchTag()
    {
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "req", "emmc"],
            includeArm32InlineTagCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(
            ["program", "read", "nop", "vendorcommand", "sig"],
            result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
        Assert.DoesNotContain(result.Commands, command => command.Name == "emmc");
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[4].Source);
    }

    [Fact]
    public void TryAnalyze_Arm32SavedValueWithoutTagGetter_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig"],
            includeArm32InlineTagCode: true);
        WriteUInt32(image, 0x200, 0xE1A00000u); // NOP replaces the tag getter call.
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "sig");
    }

    [Fact]
    public void TryAnalyze_Arm32GetterReturnValueOverwritten_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig"],
            includeArm32InlineTagCode: true);
        WriteUInt32(image, 0x200 + 0xCC, EncodeArm32Move(0, 1));
        WriteUInt32(image, 0x200 + 0xD0, 0xE12FFF1Eu); // BX LR
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
    }

    [Fact]
    public void TryAnalyze_Arm32LiteralArgumentOverwritten_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig"],
            includeArm32InlineTagCode: true);
        WriteUInt32(image, 0x200 + 0x10, EncodeArm32Move(1, 2));
        WriteUInt32(image, 0x200 + 0x14, EncodeArm32BranchLink(0x100014, 0x1000E0));
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
    }

    [Fact]
    public void TryAnalyze_ThumbTagDataFlowWithoutDiagnostic_ReturnsOnlyDispatchTag()
    {
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "req", "emmc"],
            includeThumbInlineTagCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(
            ["program", "read", "nop", "vendorcommand", "sig"],
            result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
        Assert.DoesNotContain(result.Commands, command => command.Name == "emmc");
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[4].Source);
    }

    [Fact]
    public void TryAnalyze_ThumbSavedValueWithoutTagGetter_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeThumbInlineTagCode: true);
        WriteUInt16(image, 0x200, 0xBF00); // NOP
        WriteUInt16(image, 0x202, 0xBF00); // NOP replaces the tag getter call.
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.DoesNotContain(result.Commands, command => command.Name == "sig");
    }

    [Fact]
    public void TryAnalyze_ThumbGetterReturnValueOverwritten_DoesNotReportSig()
    {
        string[] commandNames = ["program", "read", "nop", "vendorcommand"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig"],
            includeThumbInlineTagCode: true);
        WriteUInt16(image, 0x200 + 0xC6, EncodeThumbMove(0, 1));
        WriteUInt16(image, 0x200 + 0xC8, 0x4770); // BX LR
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
    }

    [Fact]
    public void TryAnalyze_Thumb32SecondHalfword_DoesNotCreateInlineCommand()
    {
        string[] tableCommands = ["program", "read", "nop", "configure"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: tableCommands,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["vendorcommand"]);

        const int codeOffset = 0x200;
        const ulong codeAddress = 0x100000;
        const ulong programAddress = 0x200200;
        const ulong vendorAddress = 0x20021B;
        const int firstLiteralOffset = 0x100;
        const int secondLiteralOffset = 0x104;
        const int comparatorOffset = 0x180;

        // These are unrelated Thumb-2 instructions whose second halfwords are
        // deliberately shaped like 16-bit literal loads.
        WriteUInt16(image, codeOffset, 0xF04F);
        WriteUInt16(
            image,
            codeOffset + 0x02,
            EncodeThumbLiteralLoad(
                1,
                codeAddress + 0x02,
                codeAddress + firstLiteralOffset));
        WriteUInt16(image, codeOffset + 0x04, EncodeThumbMove(0, 5));
        WriteThumbBranchLink(
            image,
            codeOffset,
            0x06,
            EncodeThumbBranchLink(codeAddress + 0x06, codeAddress + comparatorOffset));

        WriteUInt16(image, codeOffset + 0x0A, 0xF04F);
        WriteUInt16(
            image,
            codeOffset + 0x0C,
            EncodeThumbLiteralLoad(
                1,
                codeAddress + 0x0C,
                codeAddress + secondLiteralOffset));
        WriteUInt16(image, codeOffset + 0x0E, EncodeThumbMove(0, 5));
        WriteThumbBranchLink(
            image,
            codeOffset,
            0x10,
            EncodeThumbBranchLink(codeAddress + 0x10, codeAddress + comparatorOffset));
        WriteUInt16(image, codeOffset + 0x14, 0x4770);
        WriteUInt16(image, codeOffset + comparatorOffset, 0x4770);
        WriteUInt32(image, codeOffset + firstLiteralOffset, checked((uint)programAddress));
        WriteUInt32(image, codeOffset + secondLiteralOffset, checked((uint)vendorAddress));

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(tableCommands, result.Commands.Select(command => command.Name));
    }

    [Fact]
    public void TryAnalyze_ThumbComparisonChainWithoutCommandTable_ReturnsInlineCommands()
    {
        string[] inlineCommands =
        [
            "configure",
            "program",
            "read",
            "nop",
            "patch",
            "erase",
            "sig"
        ];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: inlineCommands,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: ["req"],
            includeCommandTable: false,
            includeThumbComparisonChainCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(inlineCommands.Length, result.Commands.Count);
        Assert.All(
            inlineCommands,
            expected => Assert.Contains(result.Commands, command => command.Name == expected));
        Assert.All(
            result.Commands,
            command =>
            {
                Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source);
                Assert.Null(command.TableEntryAddress);
                Assert.Null(command.HandlerAddress);
            });
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
    }

    [Fact]
    public void TryAnalyze_ThumbRegisterComparatorPreloadedBeforeCommandName_ReturnsInlineCommands()
    {
        string[] inlineCommands =
        [
            "configure", "program", "read", "nop", "patch", "erase", "sig"
        ];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: inlineCommands,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: ["req"],
            includeCommandTable: false,
            includeThumbRegisterComparisonChainCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(inlineCommands, result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands,
            command => Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source));
    }

    [Fact]
    public void TryAnalyze_Arm32RegisterComparatorPreloadedBeforeCommandName_ReturnsInlineCommands()
    {
        string[] inlineCommands =
        [
            "configure", "program", "read", "nop", "patch", "erase", "sig"
        ];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: inlineCommands,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: ["req"],
            includeCommandTable: false,
            includeArm32RegisterComparisonChainCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(inlineCommands, result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands,
            command => Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source));
    }

    [Fact]
    public void TryAnalyze_GenericTagDiagnosticWithoutOnlyPhrase_ReturnsInlineTag()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "req", "emmc"],
            inlineDiagnostic: "Authentication rejected: unsupported tag sig");
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("sig", result.Commands[^1].Name);
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[^1].Source);
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
        Assert.DoesNotContain(result.Commands, command => command.Name == "unsupported");
    }

    [Theory]
    [InlineData("req")]
    [InlineData("storage_type")]
    public void TryAnalyze_AttributeValueInTagDiagnostic_DoesNotReportCommand(string token)
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: [token],
            inlineDiagnostic: $"Authentication rejected: unsupported tag {token}");
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.DoesNotContain(result.Commands, command => command.Name == token);
    }

    [Fact]
    public void TryParse_FirehoseElf_IncludesCommandsInNormalParseResult()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "vendorcommand"],
            includeDispatchText: true,
            includeSigDiagnostic: true,
            extraStrings: ["req"],
            includeQualcommHashSegment: true);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out QcomImageParseResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("ELF", result.ImageFormat);
        Assert.Equal(
            ["program", "read", "nop", "vendorcommand", "sig"],
            result.SupportedCommands.Select(command => command.Name));
    }

    [Fact]
    public void TryParse_FirehoseAnalysisDisabled_DoesNotIncludeCommands()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop", "configure"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeQualcommHashSegment: true);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            AnalyzeFirehoseCommands = false,
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out QcomImageParseResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.True(result.IsProgrammer);
        Assert.Empty(result.SupportedCommands);
    }

    [Fact]
    public void TryAnalyze_UnalignedNestedElf32AndThumbHandlers_ReturnsVendorCommand()
    {
        const int prefixLength = 5;
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength,
            machine: 40,
            commands: ["configure", "nop", "program", "vendor_extension"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(1, result.AnalyzedElfCount);
        Assert.Equal(4, result.Commands.Count);
        Assert.All(result.Commands, command => Assert.Equal(prefixLength, command.ElfImageOffset));
        Assert.All(
            result.Commands,
            command => Assert.Equal(1ul, command.HandlerAddress!.Value & 1ul));
        Assert.Contains(result.Commands, command => command.Name == "vendor_extension");
    }

    [Fact]
    public void TryAnalyze_Elf32InlineNameTable_ReturnsCommandTableCommands()
    {
        string[] commandNames = ["configure", "program", "nop", "read"];
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: [],
            useInlineNameCommandTable: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        for (int index = 0; index < result.Commands.Count; index++)
        {
            FirehoseCommandInfo command = result.Commands[index];
            Assert.Equal(FirehoseCommandSource.CommandTable, command.Source);
            Assert.Equal(0x200000ul + checked((ulong)(index * 0x24)), command.TableEntryAddress);
            Assert.Equal(0x100011ul + checked((ulong)(index * 4)), command.HandlerAddress);
        }
    }

    [Fact]
    public void TryAnalyze_Elf64InlineNameTable_ReturnsCommandTableCommands()
    {
        string[] commandNames = ["configure", "program", "nop", "read"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: [],
            useInlineNameCommandTable: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        for (int index = 0; index < result.Commands.Count; index++)
        {
            FirehoseCommandInfo command = result.Commands[index];
            Assert.Equal(FirehoseCommandSource.CommandTable, command.Source);
            Assert.Equal(0x200000ul + checked((ulong)(index * 0x28)), command.TableEntryAddress);
            Assert.Equal(0x100010ul + checked((ulong)(index * 4)), command.HandlerAddress);
        }
    }

    [Fact]
    public void TryAnalyze_Elf64InlineNameTableAndAuthenticationTag_ReturnsSig()
    {
        string[] commandNames = ["configure", "program", "nop", "read"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: ["sig", "req", "emmc"],
            includeInlineTagCode: true,
            useInlineNameCommandTable: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal([.. commandNames, "sig"], result.Commands.Select(command => command.Name));
        Assert.Equal(FirehoseCommandSource.InlineDispatch, result.Commands[^1].Source);
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
    }

    [Fact]
    public void TryAnalyze_Arm64CoreComparisonChainWithoutTable_ReturnsInlineCommands()
    {
        string[] commandNames = ["configure", "program", "read", "nop", "sig"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: ["req"],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands,
            command => Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source));
        Assert.DoesNotContain(result.Commands, command => command.Name == "req");
    }

    [Fact]
    public void TryAnalyze_Arm64ComparisonsUsingDifferentFunctions_DoesNotMergeCandidates()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["configure", "program"],
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true,
            splitArm64ComparatorTargets: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Empty(result.Commands);
    }

    [Fact]
    public void TryAnalyze_Arm64RegisterBranchBetweenCandidates_DoesNotMergeFunctions()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["configure", "program"],
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true,
            arm64CandidateBoundaryInstruction: 0xD61F0120u); // BR X9
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Empty(result.Commands);
    }

    [Fact]
    public void TryAnalyze_Arm64OverwrittenTagRegister_DoesNotReportCommands()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["configure", "program"],
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true,
            arm64InterveningInstruction: 0xD2800016u);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Empty(result.Commands);
    }

    [Theory]
    [InlineData(0x3DC00016u)] // LDR Q22, [X0]
    [InlineData(0xD8000016u)] // PRFM literal with an Rt-shaped value of 22
    public void TryAnalyze_Arm64NonGprInstructionDoesNotOverwriteTagRegister_ReturnsCommands(
        uint interveningInstruction)
    {
        string[] commandNames = ["configure", "program"];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: commandNames,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true,
            arm64InterveningInstruction: interveningInstruction);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
    }

    [Theory]
    [InlineData(0xF80086C0u)] // STR X0, [X22], #8 writes back X22.
    [InlineData(0xA9405C16u)] // LDP X22, X23, [X0]
    public void TryAnalyze_Arm64LoadStoreOverwrite_DoesNotReportCommands(
        uint interveningInstruction)
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["configure", "program"],
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeArm64ComparisonChainCode: true,
            arm64InterveningInstruction: interveningInstruction);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Empty(result.Commands);
    }

    [Fact]
    public void TryAnalyze_Arm64PackedCommandPoolWithoutTable_ReturnsInlineCommands()
    {
        string[] commandNames =
        [
            "program",
            "read",
            "nop",
            "patch",
            "configure",
            "erase",
            "vendorcommand"
        ];
        string[] poolNames = ["value64", .. commandNames];
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: poolNames,
            includeDispatchText: false,
            includeSigDiagnostic: false,
            extraStrings: [],
            includeCommandTable: false,
            includeCallingHandlerOnly: true);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        Assert.All(
            result.Commands,
            command => Assert.Equal(FirehoseCommandSource.InlineDispatch, command.Source));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryAnalyze_SblMbnCommandTable_SupportsArm32AndArm64(bool isArm64)
    {
        string[] commandNames = ["program", "read", "nop", "patch", "configure", "erase"];
        byte[] image = CreateSblMbn(isArm64, commandNames);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(1, result.AnalyzedElfCount);
        Assert.Equal(commandNames, result.Commands.Select(command => command.Name));
        int entrySize = 32 + (isArm64 ? sizeof(ulong) : sizeof(uint));
        ulong mappedAddress = isArm64 ? 0xF800C000ul : 0xF800C050ul;
        for (int index = 0; index < result.Commands.Count; index++)
        {
            FirehoseCommandInfo command = result.Commands[index];
            Assert.Equal(FirehoseCommandSource.CommandTable, command.Source);
            Assert.Equal(
                mappedAddress + checked((ulong)(index * entrySize)),
                command.TableEntryAddress);
            Assert.Equal(
                mappedAddress + 0x400ul + checked((ulong)(index * 4)),
                command.HandlerAddress);
        }
    }

    [Fact]
    public void TryAnalyze_NonFirehoseFunctionTable_DoesNotReportCommands()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["clockinit", "power", "ufs", "storageinit"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.False(result.IsSuccess);
        Assert.Empty(result.Commands);
        Assert.Contains("未发现可信", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, 40)]
    [InlineData(false, 183)]
    public void TryAnalyze_ArmMachineAndElfClassMismatch_IsRejected(
        bool is64Bit,
        ushort machine)
    {
        byte[] image = CreateElf(
            is64Bit: is64Bit,
            prefixLength: 0,
            machine: machine,
            commands: ["program", "read", "nop", "patch", "configure", "erase"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
    }

    [Fact]
    public void TryAnalyze_NonArmElf_IsRejected()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 62,
            commands: ["program", "read", "nop", "patch", "configure", "erase"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
    }

    [Fact]
    public void TryAnalyze_TruncatedElf_ReturnsStructuralError()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        Array.Resize(ref image, 100);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
        Assert.Contains("未识别到有效", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void TryAnalyze_OverflowingProgramHeaderOffset_ReturnsStructuralError()
    {
        var image = new byte[64];
        image[0] = 0x7F;
        image[1] = (byte)'E';
        image[2] = (byte)'L';
        image[3] = (byte)'F';
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        WriteUInt64(image, 32, ulong.MaxValue);
        WriteUInt16(image, 52, 64);
        WriteUInt16(image, 54, 56);
        WriteUInt16(image, 56, 1);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
        Assert.Contains("未识别到有效", result.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void TryAnalyze_Elf64VirtualAddressRangeWraps_ReturnsStructuralError()
    {
        byte[] image = CreateElf(
            is64Bit: true,
            prefixLength: 0,
            machine: 183,
            commands: ["program", "read", "nop"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        WriteUInt64(image, 64 + 16, ulong.MaxValue - 0x10);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
    }

    [Fact]
    public void TryAnalyze_Elf32VirtualAddressExceedsAddressSpace_ReturnsStructuralError()
    {
        byte[] image = CreateElf(
            is64Bit: false,
            prefixLength: 0,
            machine: 40,
            commands: ["program", "read", "nop"],
            includeDispatchText: true,
            includeSigDiagnostic: false,
            extraStrings: []);
        WriteUInt32(image, 52 + 8, 0xFFFFFFF0);
        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.False(success);
        Assert.Equal(0, result.AnalyzedElfCount);
    }

    [Fact]
    public void Constructor_InvalidLimits_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FirehoseCommandAnalyzer(new FirehoseCommandAnalyzerOptions
            {
                MinimumCommandTableEntries = 1
            }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FirehoseCommandAnalyzer(new FirehoseCommandAnalyzerOptions
            {
                MaximumElfCount = 0
            }));
    }

    private static byte[] ExpandElf64CodeSegment(
        byte[] image,
        int codeSize,
        int dataOffset)
    {
        const int elfHeaderSize = 64;
        const int programHeaderSize = 56;
        const int codeFileOffset = 0x200;
        const int oldDataOffset = 0x400;
        Assert.True(codeSize >= oldDataOffset - codeFileOffset);
        Assert.True(dataOffset >= codeFileOffset + codeSize);

        int dataLength = image.Length - oldDataOffset;
        var expanded = new byte[dataOffset + dataLength];
        image.AsSpan(0, oldDataOffset).CopyTo(expanded);
        image.AsSpan(oldDataOffset).CopyTo(expanded.AsSpan(dataOffset));

        int codeProgramHeader = elfHeaderSize;
        int dataProgramHeader = elfHeaderSize + programHeaderSize;
        WriteUInt64(expanded, codeProgramHeader + 32, checked((ulong)codeSize));
        WriteUInt64(expanded, codeProgramHeader + 40, checked((ulong)codeSize));
        WriteUInt64(expanded, dataProgramHeader + 8, checked((ulong)dataOffset));
        return expanded;
    }

    private static byte[] CreateSblMbn(bool isArm64, IReadOnlyList<string> commands)
    {
        const int headerSize = 0x50;
        const int payloadSize = 0x500;
        ulong mappedAddress = isArm64 ? 0xF800C000ul : 0xF800C050ul;
        int pointerSize = isArm64 ? sizeof(ulong) : sizeof(uint);
        int entrySize = 32 + pointerSize;
        var image = new byte[headerSize + payloadSize];

        WriteUInt32(image, 0, 0x844BDCD1);
        WriteUInt32(image, 4, 0x73D71034);
        WriteUInt32(image, 8, isArm64 ? 0x15u : 0x0Du);
        WriteUInt32(image, 20, headerSize);
        WriteUInt32(image, 24, checked((uint)mappedAddress));
        WriteUInt32(image, 28, payloadSize);
        WriteUInt32(image, 32, payloadSize);
        WriteUInt32(image, 60, isArm64 ? 0xFu : uint.MaxValue);

        for (int index = 0; index < commands.Count; index++)
        {
            int entryOffset = headerSize + index * entrySize;
            WriteAsciiAt(image, entryOffset, commands[index]);
            WritePointer(
                image,
                entryOffset + 32,
                pointerSize,
                mappedAddress + 0x400ul + checked((ulong)(index * 4)));
        }

        return image;
    }

    private static byte[] CreateElf(
        bool is64Bit,
        int prefixLength,
        ushort machine,
        IReadOnlyList<string> commands,
        bool includeDispatchText,
        bool includeSigDiagnostic,
        IReadOnlyList<string> extraStrings,
        bool includeQualcommHashSegment = false,
        bool includeInlineTagCode = false,
        string? inlineDiagnostic = null,
        bool includeArm32InlineTagCode = false,
        bool includeThumbInlineTagCode = false,
        bool includeCommandTable = true,
        bool includeThumbComparisonChainCode = false,
        bool useInlineNameCommandTable = false,
        bool includeCallingHandlerOnly = false,
        bool includeArm64ComparisonChainCode = false,
        bool splitArm64ComparatorTargets = false,
        uint? arm64InterveningInstruction = null,
        bool includeThumbRegisterComparisonChainCode = false,
        bool includeArm32RegisterComparisonChainCode = false,
        bool useArm64RegisterGetterCall = false,
        uint? arm64CandidateBoundaryInstruction = null)
    {
        const int codeOffset = 0x200;
        const int dataOffset = 0x400;
        const int hashOffset = 0xC00;
        const int codeSize = 0x200;
        const int dataSize = 0x800;
        const ulong codeAddress = 0x100000;
        const ulong dataAddress = 0x200000;
        const ulong hashAddress = 0x300000;
        int headerSize = is64Bit ? 64 : 52;
        int programHeaderSize = is64Bit ? 56 : 32;
        int pointerSize = is64Bit ? 8 : 4;
        byte[] hashSegment = includeQualcommHashSegment
            ? BinaryImageFactory.CreateHashSegment(3)
            : [];
        int programHeaderCount = includeQualcommHashSegment ? 3 : 2;
        int imageLength = includeQualcommHashSegment
            ? prefixLength + hashOffset + hashSegment.Length
            : prefixLength + dataOffset + dataSize;
        var image = new byte[imageLength];
        Span<byte> elf = image.AsSpan(prefixLength);

        elf[0] = 0x7F;
        elf[1] = (byte)'E';
        elf[2] = (byte)'L';
        elf[3] = (byte)'F';
        elf[4] = is64Bit ? (byte)2 : (byte)1;
        elf[5] = 1;
        elf[6] = 1;
        WriteUInt16(elf, 16, 2);
        WriteUInt16(elf, 18, machine);
        WriteUInt32(elf, 20, 1);

        if (is64Bit)
        {
            WriteUInt64(elf, 24, codeAddress);
            WriteUInt64(elf, 32, checked((ulong)headerSize));
            WriteUInt16(elf, 52, checked((ushort)headerSize));
            WriteUInt16(elf, 54, checked((ushort)programHeaderSize));
            WriteUInt16(elf, 56, checked((ushort)programHeaderCount));
        }
        else
        {
            ulong entryAddress = includeThumbInlineTagCode
                                 || includeThumbComparisonChainCode
                                 || includeThumbRegisterComparisonChainCode
                ? codeAddress | 1ul
                : codeAddress;
            WriteUInt32(elf, 24, checked((uint)entryAddress));
            WriteUInt32(elf, 28, checked((uint)headerSize));
            WriteUInt16(elf, 40, checked((ushort)headerSize));
            WriteUInt16(elf, 42, checked((ushort)programHeaderSize));
            WriteUInt16(elf, 44, checked((ushort)programHeaderCount));
        }

        WriteProgramHeader(
            elf,
            headerSize,
            is64Bit,
            codeOffset,
            codeAddress,
            codeSize,
            flags: 5);
        WriteProgramHeader(
            elf,
            headerSize + programHeaderSize,
            is64Bit,
            dataOffset,
            dataAddress,
            dataSize,
            flags: 6);
        if (includeQualcommHashSegment)
        {
            WriteProgramHeader(
                elf,
                headerSize + programHeaderSize * 2,
                is64Bit,
                hashOffset,
                hashAddress,
                hashSegment.Length,
                flags: 0x02200000);
            hashSegment.CopyTo(elf.Slice(hashOffset, hashSegment.Length));
        }

        int stringOffset = dataOffset + 0x200;
        var commandAddresses = new ulong[commands.Count];
        var stringAddresses = new Dictionary<string, ulong>(StringComparer.Ordinal);
        for (int index = 0; index < commands.Count; index++)
        {
            commandAddresses[index] = WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                commands[index]);
            stringAddresses[commands[index]] = commandAddresses[index];
        }
        for (int index = 0; index < extraStrings.Count; index++)
        {
            ulong address = WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                extraStrings[index]);
            stringAddresses[extraStrings[index]] = address;
        }
        if (includeDispatchText)
        {
            WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                "Supported Functions (%d):");
            WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                "Calling handler for %s");
        }
        else if (includeCallingHandlerOnly)
        {
            WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                "Calling handler for %s");
        }
        if (includeSigDiagnostic)
        {
            WriteString(elf, dataAddress, dataOffset, ref stringOffset, "sig");
            WriteString(
                elf,
                dataAddress,
                dataOffset,
                ref stringOffset,
                "Only nop and sig tag can be received before authentication.");
        }
        if (inlineDiagnostic is not null)
            WriteString(elf, dataAddress, dataOffset, ref stringOffset, inlineDiagnostic);

        if (includeCommandTable)
        {
            for (int index = 0; index < commands.Count; index++)
            {
                int entrySize = useInlineNameCommandTable ? 32 + pointerSize : pointerSize * 2;
                int entryOffset = dataOffset + index * entrySize;
                ulong handlerAddress = codeAddress + checked((ulong)(0x10 + index * 4));
                if (!is64Bit && machine == 40)
                    handlerAddress |= 1;
                if (useInlineNameCommandTable)
                {
                    Assert.True(Encoding.ASCII.GetByteCount(commands[index]) < 32);
                    WriteAsciiAt(elf, entryOffset, commands[index]);
                    WritePointer(elf, entryOffset + 32, pointerSize, handlerAddress);
                }
                else
                {
                    WritePointer(elf, entryOffset, pointerSize, commandAddresses[index]);
                    WritePointer(elf, entryOffset + pointerSize, pointerSize, handlerAddress);
                }
            }
        }

        if (includeInlineTagCode)
        {
            Assert.True(is64Bit);
            Assert.Equal((ushort)183, machine);
            WriteArm64InlineDispatchCode(
                elf,
                codeOffset,
                codeAddress,
                dataAddress,
                stringAddresses["sig"],
                stringAddresses["emmc"],
                useArm64RegisterGetterCall);
        }
        if (includeArm32InlineTagCode)
        {
            Assert.False(is64Bit);
            Assert.Equal((ushort)40, machine);
            WriteArm32InlineDispatchCode(
                elf,
                codeOffset,
                codeAddress,
                dataAddress,
                stringAddresses["sig"]);
        }
        if (includeThumbInlineTagCode)
        {
            Assert.False(is64Bit);
            Assert.Equal((ushort)40, machine);
            WriteThumbInlineDispatchCode(elf, codeOffset, codeAddress, dataAddress);
        }
        if (includeThumbComparisonChainCode)
        {
            Assert.False(is64Bit);
            Assert.Equal((ushort)40, machine);
            Assert.False(includeCommandTable);
            WriteThumbComparisonChainCode(elf, codeOffset, codeAddress, commands);
        }
        if (includeThumbRegisterComparisonChainCode)
        {
            Assert.False(is64Bit);
            Assert.Equal((ushort)40, machine);
            Assert.False(includeCommandTable);
            WriteThumbRegisterComparisonChainCode(
                elf,
                codeOffset,
                codeAddress,
                commands);
        }
        if (includeArm32RegisterComparisonChainCode)
        {
            Assert.False(is64Bit);
            Assert.Equal((ushort)40, machine);
            Assert.False(includeCommandTable);
            WriteArm32RegisterComparisonChainCode(
                elf,
                codeOffset,
                codeAddress,
                commands);
        }
        if (includeArm64ComparisonChainCode)
        {
            Assert.True(is64Bit);
            Assert.Equal((ushort)183, machine);
            Assert.False(includeCommandTable);
            WriteArm64ComparisonChainCode(
                elf,
                codeOffset,
                codeAddress,
                commandAddresses,
                splitArm64ComparatorTargets,
                arm64InterveningInstruction,
                arm64CandidateBoundaryInstruction);
        }

        return image;
    }

    private static void WriteArm32InlineDispatchCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        ulong commandTableAddress,
        ulong sigAddress)
    {
        const int getterOffset = 0xC0;
        const int compareOffset = 0xE0;
        const int sigLiteralOffset = 0x30;
        const int tableLiteralOffset = 0x34;
        ulong getterAddress = codeAddress + getterOffset;
        ulong compareAddress = codeAddress + compareOffset;

        WriteArm32Instruction(image, codeOffset, 0x00, EncodeArm32BranchLink(codeAddress, getterAddress));
        WriteArm32Instruction(image, codeOffset, 0x04, EncodeArm32Move(4, 0));
        WriteArm32Instruction(
            image,
            codeOffset,
            0x08,
            EncodeArm32LiteralLoad(1, codeAddress + 0x08, codeAddress + sigLiteralOffset));
        WriteArm32Instruction(image, codeOffset, 0x0C, EncodeArm32Move(0, 4));
        WriteArm32Instruction(image, codeOffset, 0x10, EncodeArm32BranchLink(codeAddress + 0x10, compareAddress));
        WriteArm32Instruction(
            image,
            codeOffset,
            0x14,
            EncodeArm32LiteralLoad(8, codeAddress + 0x14, codeAddress + tableLiteralOffset));
        WriteArm32Instruction(image, codeOffset, 0x18, EncodeArm32BranchExchange(10));
        WriteArm32Instruction(image, codeOffset, 0x1C, 0xE12FFF1Eu); // BX LR

        WriteArm32Instruction(image, codeOffset, getterOffset, 0xE5D01000u); // LDRB R1, [R0]
        WriteArm32Instruction(image, codeOffset, getterOffset + 0x04, 0xE5902008u); // LDR R2, [R0,#8]
        WriteArm32Instruction(image, codeOffset, getterOffset + 0x08, EncodeArm32Move(0, 2));
        WriteArm32Instruction(image, codeOffset, getterOffset + 0x0C, 0xE12FFF1Eu); // BX LR
        WriteArm32Instruction(image, codeOffset, compareOffset, 0xE12FFF1Eu); // BX LR

        WriteUInt32(image, codeOffset + sigLiteralOffset, checked((uint)sigAddress));
        WriteUInt32(image, codeOffset + tableLiteralOffset, checked((uint)commandTableAddress));
    }

    private static void WriteThumbInlineDispatchCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        ulong commandTableAddress)
    {
        const int getterOffset = 0xC0;
        const int compareOffset = 0xE0;
        const int sigStringOffset = 0x120;
        const int tableLiteralOffset = 0x2C;
        ulong getterAddress = codeAddress + getterOffset;
        ulong compareAddress = codeAddress + compareOffset;

        WriteThumbBranchLink(image, codeOffset, 0x00, EncodeThumbBranchLink(codeAddress, getterAddress));
        WriteUInt16(image, codeOffset + 0x04, EncodeThumbMove(4, 0));
        WriteUInt16(
            image,
            codeOffset + 0x06,
            EncodeThumbAdr(codeAddress + 0x06, 1, codeAddress + sigStringOffset));
        WriteUInt16(image, codeOffset + 0x08, EncodeThumbMove(0, 4));
        WriteThumbBranchLink(image, codeOffset, 0x0A, EncodeThumbBranchLink(codeAddress + 0x0A, compareAddress));
        WriteUInt16(
            image,
            codeOffset + 0x0E,
            EncodeThumbLiteralLoad(6, codeAddress + 0x0E, codeAddress + tableLiteralOffset));
        WriteUInt16(image, codeOffset + 0x10, EncodeThumbBranchExchange(3));
        WriteUInt16(image, codeOffset + 0x12, 0x4770); // BX LR

        WriteUInt16(image, codeOffset + getterOffset, 0x7801); // LDRB R1, [R0]
        WriteUInt16(image, codeOffset + getterOffset + 0x02, 0x6882); // LDR R2, [R0,#8]
        WriteUInt16(image, codeOffset + getterOffset + 0x04, EncodeThumbMove(0, 2));
        WriteUInt16(image, codeOffset + getterOffset + 0x06, 0x4770); // BX LR
        WriteUInt16(image, codeOffset + compareOffset, 0x4770); // BX LR

        WriteUInt32(image, codeOffset + tableLiteralOffset, checked((uint)commandTableAddress));
        WriteAsciiAt(image, codeOffset + sigStringOffset, "sig");
    }

    private static void WriteThumbComparisonChainCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        IReadOnlyList<string> commands)
    {
        const int compareOffset = 0xE0;
        const int handlerOffset = 0x100;
        const int stringOffset = 0x120;
        ulong compareAddress = codeAddress + compareOffset;
        ulong handlerAddress = codeAddress + handlerOffset;

        WriteUInt16(image, codeOffset, EncodeThumbMove(5, 0));
        int instructionOffset = 0x02;
        int currentStringOffset = stringOffset;
        for (int index = 0; index < commands.Count; index++)
        {
            WriteUInt16(
                image,
                codeOffset + instructionOffset,
                EncodeThumbAdr(
                    codeAddress + checked((ulong)instructionOffset),
                    1,
                    codeAddress + checked((ulong)currentStringOffset)));
            WriteUInt16(image, codeOffset + instructionOffset + 0x02, EncodeThumbMove(0, 5));
            WriteThumbBranchLink(
                image,
                codeOffset,
                instructionOffset + 0x04,
                EncodeThumbBranchLink(
                    codeAddress + checked((ulong)(instructionOffset + 0x04)),
                    compareAddress));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x08,
                EncodeThumbCompareAndBranchZero(
                    0,
                    codeAddress + checked((ulong)(instructionOffset + 0x08)),
                    codeAddress + checked((ulong)(instructionOffset + 0x10))));
            WriteThumbBranchLink(
                image,
                codeOffset,
                instructionOffset + 0x0A,
                EncodeThumbBranchLink(
                    codeAddress + checked((ulong)(instructionOffset + 0x0A)),
                    handlerAddress));
            WriteUInt16(image, codeOffset + instructionOffset + 0x0E, 0xBD30); // POP {R4,R5,PC}
            instructionOffset += 0x10;
            WriteAsciiAt(image, codeOffset + currentStringOffset, commands[index]);
            currentStringOffset += (Encoding.ASCII.GetByteCount(commands[index]) + 1 + 3) & ~3;
        }

        WriteUInt16(image, codeOffset + instructionOffset, 0x4770); // BX LR
        WriteUInt16(image, codeOffset + compareOffset, 0x4770); // BX LR
        WriteUInt16(image, codeOffset + handlerOffset, 0x4770); // BX LR
    }

    private static void WriteThumbRegisterComparisonChainCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        IReadOnlyList<string> commands)
    {
        const int compareOffset = 0xE0;
        const int handlerOffset = 0x100;
        const int stringOffset = 0x120;
        const int comparatorLiteralOffset = 0x1F0;
        ulong compareAddress = codeAddress + compareOffset;
        ulong handlerAddress = codeAddress + handlerOffset;

        WriteUInt16(image, codeOffset, EncodeThumbMove(5, 0));
        int instructionOffset = 0x02;
        int currentStringOffset = stringOffset;
        for (int index = 0; index < commands.Count; index++)
        {
            WriteUInt16(
                image,
                codeOffset + instructionOffset,
                EncodeThumbLiteralLoad(
                    7,
                    codeAddress + checked((ulong)instructionOffset),
                    codeAddress + comparatorLiteralOffset));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x02,
                EncodeThumbAdr(
                    codeAddress + checked((ulong)(instructionOffset + 0x02)),
                    1,
                    codeAddress + checked((ulong)currentStringOffset)));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x04,
                EncodeThumbMove(0, 5));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x06,
                EncodeThumbBranchExchange(7));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x08,
                EncodeThumbCompareAndBranchZero(
                    0,
                    codeAddress + checked((ulong)(instructionOffset + 0x08)),
                    codeAddress + checked((ulong)(instructionOffset + 0x10))));
            WriteThumbBranchLink(
                image,
                codeOffset,
                instructionOffset + 0x0A,
                EncodeThumbBranchLink(
                    codeAddress + checked((ulong)(instructionOffset + 0x0A)),
                    handlerAddress));
            WriteUInt16(
                image,
                codeOffset + instructionOffset + 0x0E,
                0xBD30); // POP {R4,R5,PC}
            instructionOffset += 0x10;
            WriteAsciiAt(image, codeOffset + currentStringOffset, commands[index]);
            currentStringOffset += (Encoding.ASCII.GetByteCount(commands[index]) + 1 + 3) & ~3;
        }

        WriteUInt16(image, codeOffset + instructionOffset, 0x4770); // BX LR
        WriteUInt16(image, codeOffset + compareOffset, 0x4770); // BX LR
        WriteUInt16(image, codeOffset + handlerOffset, 0x4770); // BX LR
        WriteUInt32(
            image,
            codeOffset + comparatorLiteralOffset,
            checked((uint)(compareAddress | 1UL)));
    }

    private static void WriteArm32RegisterComparisonChainCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        IReadOnlyList<string> commands)
    {
        const int compareOffset = 0xD0;
        const int handlerOffset = 0xD4;
        const int stringOffset = 0xE0;
        const int comparatorLiteralOffset = 0x1F0;
        ulong compareAddress = codeAddress + compareOffset;
        ulong handlerAddress = codeAddress + handlerOffset;

        WriteArm32Instruction(image, codeOffset, 0, EncodeArm32Move(5, 0));
        int instructionOffset = sizeof(uint);
        int currentStringOffset = stringOffset;
        for (int index = 0; index < commands.Count; index++)
        {
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset,
                EncodeArm32LiteralLoad(
                    7,
                    codeAddress + checked((ulong)instructionOffset),
                    codeAddress + comparatorLiteralOffset));
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x04,
                EncodeArm32Adr(
                    codeAddress + checked((ulong)(instructionOffset + 0x04)),
                    1,
                    codeAddress + checked((ulong)currentStringOffset)));
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x08,
                EncodeArm32Move(0, 5));
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x0C,
                EncodeArm32BranchExchange(7));
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x10,
                0x1A000000u); // BNE +0
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x14,
                EncodeArm32BranchLink(
                    codeAddress + checked((ulong)(instructionOffset + 0x14)),
                    handlerAddress));
            WriteArm32Instruction(
                image,
                codeOffset,
                instructionOffset + 0x18,
                0xE8BD8030u); // POP {R4,R5,PC}
            instructionOffset += 0x1C;
            WriteAsciiAt(image, codeOffset + currentStringOffset, commands[index]);
            currentStringOffset += (Encoding.ASCII.GetByteCount(commands[index]) + 1 + 3) & ~3;
        }

        WriteArm32Instruction(image, codeOffset, compareOffset, 0xE12FFF1Eu); // BX LR
        WriteArm32Instruction(image, codeOffset, handlerOffset, 0xE12FFF1Eu); // BX LR
        WriteUInt32(
            image,
            codeOffset + comparatorLiteralOffset,
            checked((uint)compareAddress));
    }

    private static void WriteArm64InlineDispatchCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        ulong commandTableAddress,
        ulong sigAddress,
        ulong nonDispatchTagAddress,
        bool useRegisterGetterCall)
    {
        const int getterOffset = 0xC0;
        const int compareOffset = 0xE0;
        ulong getterAddress = codeAddress + getterOffset;
        ulong compareAddress = codeAddress + compareOffset;

        int instructionOffset = 0;
        if (useRegisterGetterCall)
        {
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset,
                EncodeArm64Adrp(codeAddress, getterAddress, 9));
            instructionOffset += sizeof(uint);
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset,
                EncodeArm64AddAddress(getterAddress, 9));
            instructionOffset += sizeof(uint);
            WriteArm64Instruction(image, codeOffset, instructionOffset, 0xD63F0120u); // BLR X9
            instructionOffset += sizeof(uint);
        }
        else
        {
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset,
                EncodeArm64BranchLink(codeAddress, getterAddress));
            instructionOffset += sizeof(uint);
        }

        WriteArm64Instruction(image, codeOffset, instructionOffset, EncodeArm64Move(22, 0));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(
            image,
            codeOffset,
            instructionOffset,
            EncodeArm64Adrp(
                codeAddress + checked((ulong)instructionOffset),
                sigAddress,
                23));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(
            image,
            codeOffset,
            instructionOffset,
            EncodeArm64AddAddress(sigAddress, 23));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(image, codeOffset, instructionOffset, EncodeArm64Move(0, 22));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(image, codeOffset, instructionOffset, EncodeArm64Move(1, 23));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(
            image,
            codeOffset,
            instructionOffset,
            EncodeArm64BranchLink(
                codeAddress + checked((ulong)instructionOffset),
                compareAddress));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(
            image,
            codeOffset,
            instructionOffset,
            EncodeArm64Adrp(
                codeAddress + checked((ulong)instructionOffset),
                commandTableAddress,
                8));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(
            image,
            codeOffset,
            instructionOffset,
            EncodeArm64AddAddress(commandTableAddress, 8));
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(image, codeOffset, instructionOffset, 0xD63F0140u); // BLR X10
        instructionOffset += sizeof(uint);
        WriteArm64Instruction(image, codeOffset, instructionOffset, 0xD65F03C0u); // RET

        const int unrelatedOffset = 0x50;
        ulong unrelatedAddress = codeAddress + unrelatedOffset;
        WriteArm64Instruction(
            image,
            codeOffset,
            unrelatedOffset,
            EncodeArm64BranchLink(unrelatedAddress, getterAddress));
        WriteArm64Instruction(image, codeOffset, unrelatedOffset + 0x04, EncodeArm64Move(22, 0));
        WriteArm64Instruction(
            image,
            codeOffset,
            unrelatedOffset + 0x08,
            EncodeArm64Adrp(unrelatedAddress + 0x08, nonDispatchTagAddress, 23));
        WriteArm64Instruction(
            image,
            codeOffset,
            unrelatedOffset + 0x0C,
            EncodeArm64AddAddress(nonDispatchTagAddress, 23));
        WriteArm64Instruction(image, codeOffset, unrelatedOffset + 0x10, EncodeArm64Move(0, 22));
        WriteArm64Instruction(image, codeOffset, unrelatedOffset + 0x14, EncodeArm64Move(1, 23));
        WriteArm64Instruction(
            image,
            codeOffset,
            unrelatedOffset + 0x18,
            EncodeArm64BranchLink(unrelatedAddress + 0x18, compareAddress));
        WriteArm64Instruction(image, codeOffset, unrelatedOffset + 0x1C, 0xD65F03C0u); // RET

        WriteArm64Instruction(image, codeOffset, getterOffset, 0x39400009u); // LDRB W9, [X0]
        WriteArm64Instruction(image, codeOffset, getterOffset + 0x04, 0xF940080Au); // LDR X10, [X0,#0x10]
        WriteArm64Instruction(image, codeOffset, getterOffset + 0x08, EncodeArm64Move(0, 10));
        WriteArm64Instruction(image, codeOffset, getterOffset + 0x0C, 0xD65F03C0u); // RET
        WriteArm64Instruction(image, codeOffset, compareOffset, 0xD65F03C0u); // RET
    }

    private static void WriteArm64ComparisonChainCode(
        Span<byte> image,
        int codeOffset,
        ulong codeAddress,
        IReadOnlyList<ulong> commandAddresses,
        bool splitComparatorTargets,
        uint? interveningInstruction,
        uint? candidateBoundaryInstruction)
    {
        const int getterOffset = 0xC0;
        const int compareOffset = 0xE0;
        ulong getterAddress = codeAddress + getterOffset;
        ulong compareAddress = codeAddress + compareOffset;

        WriteArm64Instruction(image, codeOffset, 0, EncodeArm64BranchLink(codeAddress, getterAddress));
        WriteArm64Instruction(image, codeOffset, 4, EncodeArm64Move(22, 0));
        int instructionOffset = 8;
        if (interveningInstruction.HasValue)
        {
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset,
                interveningInstruction.Value);
            instructionOffset += 4;
        }
        for (int index = 0; index < commandAddresses.Count; index++)
        {
            ulong commandAddress = commandAddresses[index];
            ulong instructionAddress = codeAddress + checked((ulong)instructionOffset);
            ulong comparatorAddress = splitComparatorTargets
                ? compareAddress + checked((ulong)(index * 4))
                : compareAddress;
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset,
                EncodeArm64Adrp(instructionAddress, commandAddress, 23));
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset + 4,
                EncodeArm64AddAddress(commandAddress, 23));
            WriteArm64Instruction(image, codeOffset, instructionOffset + 8, EncodeArm64Move(0, 22));
            WriteArm64Instruction(image, codeOffset, instructionOffset + 12, EncodeArm64Move(1, 23));
            WriteArm64Instruction(
                image,
                codeOffset,
                instructionOffset + 16,
                EncodeArm64BranchLink(instructionAddress + 16, comparatorAddress));
            instructionOffset += 20;
            if (index == 0 && candidateBoundaryInstruction.HasValue)
            {
                WriteArm64Instruction(
                    image,
                    codeOffset,
                    instructionOffset,
                    candidateBoundaryInstruction.Value);
                instructionOffset += sizeof(uint);
            }
        }
        WriteArm64Instruction(image, codeOffset, instructionOffset, 0xD65F03C0u); // RET

        WriteArm64Instruction(image, codeOffset, getterOffset, 0x39400009u); // LDRB W9, [X0]
        WriteArm64Instruction(image, codeOffset, getterOffset + 4, 0xF940080Au); // LDR X10, [X0,#0x10]
        WriteArm64Instruction(image, codeOffset, getterOffset + 8, EncodeArm64Move(0, 10));
        WriteArm64Instruction(image, codeOffset, getterOffset + 12, 0xD65F03C0u); // RET
        int comparatorCount = splitComparatorTargets ? commandAddresses.Count : 1;
        for (int index = 0; index < comparatorCount; index++)
        {
            WriteArm64Instruction(
                image,
                codeOffset,
                compareOffset + index * 4,
                0xD65F03C0u); // RET
        }
    }

    private static void WriteArm32Instruction(
        Span<byte> image,
        int codeOffset,
        int instructionOffset,
        uint instruction)
    {
        WriteUInt32(image, codeOffset + instructionOffset, instruction);
    }

    private static void WriteThumbBranchLink(
        Span<byte> image,
        int codeOffset,
        int instructionOffset,
        uint instruction)
    {
        WriteUInt16(image, codeOffset + instructionOffset, unchecked((ushort)instruction));
        WriteUInt16(image, codeOffset + instructionOffset + 0x02, unchecked((ushort)(instruction >> 16)));
    }

    private static void WriteAsciiAt(Span<byte> image, int offset, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        bytes.CopyTo(image.Slice(offset, bytes.Length));
        image[offset + bytes.Length] = 0;
    }

    private static uint EncodeArm32BranchLink(ulong instructionAddress, ulong targetAddress)
    {
        long delta = checked((long)targetAddress - checked((long)instructionAddress + 8));
        Assert.Equal(0, delta & 3);
        long immediate = delta >> 2;
        Assert.InRange(immediate, -(1L << 23), (1L << 23) - 1);
        return 0xEB000000u | (unchecked((uint)immediate) & 0x00FFFFFFu);
    }

    private static uint EncodeArm32LiteralLoad(
        int destinationRegister,
        ulong instructionAddress,
        ulong literalAddress)
    {
        long delta = checked((long)literalAddress - checked((long)instructionAddress + 8));
        Assert.Equal(0, delta & 3);
        Assert.InRange(delta, -4095L, 4095L);
        uint opcode = delta >= 0 ? 0xE59F0000u : 0xE51F0000u;
        return opcode
               | (checked((uint)destinationRegister) << 12)
               | checked((uint)Math.Abs(delta));
    }

    private static uint EncodeArm32Adr(
        ulong instructionAddress,
        int destinationRegister,
        ulong targetAddress)
    {
        long delta = checked((long)targetAddress - checked((long)instructionAddress + 8));
        Assert.InRange(delta, 0L, 255L);
        return 0xE28F0000u
               | (checked((uint)destinationRegister) << 12)
               | checked((uint)delta);
    }

    private static uint EncodeArm32Move(int destinationRegister, int sourceRegister)
    {
        return 0xE1A00000u
               | (checked((uint)destinationRegister) << 12)
               | checked((uint)sourceRegister);
    }

    private static uint EncodeArm32BranchExchange(int register)
    {
        return 0xE12FFF30u | checked((uint)register);
    }

    private static uint EncodeThumbBranchLink(ulong instructionAddress, ulong targetAddress)
    {
        long delta = checked((long)targetAddress - checked((long)instructionAddress + 4));
        Assert.Equal(0, delta & 1);
        Assert.InRange(delta, -(1L << 24), (1L << 24) - 2);
        uint encoded = unchecked((uint)delta) & 0x01FFFFFFu;
        uint sign = (encoded >> 24) & 1u;
        uint i1 = (encoded >> 23) & 1u;
        uint i2 = (encoded >> 22) & 1u;
        uint j1 = (~(i1 ^ sign)) & 1u;
        uint j2 = (~(i2 ^ sign)) & 1u;
        ushort first = checked((ushort)(0xF000u | (sign << 10) | ((encoded >> 12) & 0x3FFu)));
        ushort second = checked((ushort)(
            0xD000u
            | (j1 << 13)
            | (j2 << 11)
            | ((encoded >> 1) & 0x7FFu)));
        return (uint)first | ((uint)second << 16);
    }

    private static ushort EncodeThumbAdr(
        ulong instructionAddress,
        int destinationRegister,
        ulong targetAddress)
    {
        ulong page = (instructionAddress + 4) & ~3UL;
        long delta = checked((long)targetAddress - checked((long)page));
        Assert.True(delta >= 0 && delta % 4 == 0);
        Assert.InRange(delta / 4, 0L, 255L);
        return checked((ushort)(0xA000u
                                | (checked((uint)destinationRegister) << 8)
                                | checked((uint)(delta / 4))));
    }

    private static ushort EncodeThumbLiteralLoad(
        int destinationRegister,
        ulong instructionAddress,
        ulong literalAddress)
    {
        ulong page = (instructionAddress + 4) & ~3UL;
        long delta = checked((long)literalAddress - checked((long)page));
        Assert.True(delta >= 0 && delta % 4 == 0);
        Assert.InRange(delta / 4, 0L, 255L);
        return checked((ushort)(0x4800u
                                | (checked((uint)destinationRegister) << 8)
                                | checked((uint)(delta / 4))));
    }

    private static ushort EncodeThumbMove(int destinationRegister, int sourceRegister)
    {
        return checked((ushort)(0x4600u
                                | (checked((uint)sourceRegister) << 3)
                                | checked((uint)(destinationRegister & 7))
                                | checked((uint)(destinationRegister & 8) << 4)));
    }

    private static ushort EncodeThumbBranchExchange(int register)
    {
        return checked((ushort)(0x4780u | (checked((uint)register) << 3)));
    }

    private static ushort EncodeThumbCompareAndBranchZero(
        int register,
        ulong instructionAddress,
        ulong targetAddress)
    {
        long delta = checked((long)targetAddress - checked((long)instructionAddress + 4));
        Assert.True(delta >= 0 && delta % 2 == 0);
        Assert.InRange(delta, 0L, 126L);
        uint encoded = checked((uint)delta);
        return checked((ushort)(0xB100u
                                | (((encoded >> 6) & 1u) << 9)
                                | (((encoded >> 1) & 0x1Fu) << 3)
                                | checked((uint)register)));
    }

    private static uint EncodeArm64BranchLink(ulong instructionAddress, ulong targetAddress)
    {
        long delta = checked((long)targetAddress - (long)instructionAddress);
        Assert.Equal(0, delta & 3);
        long immediate = delta >> 2;
        Assert.InRange(immediate, -(1L << 25), (1L << 25) - 1);
        return 0x94000000u | (unchecked((uint)immediate) & 0x03FFFFFFu);
    }

    private static uint EncodeArm64Branch(ulong instructionAddress, ulong targetAddress)
    {
        long delta = checked((long)targetAddress - (long)instructionAddress);
        Assert.Equal(0, delta & 3);
        long immediate = delta >> 2;
        Assert.InRange(immediate, -(1L << 25), (1L << 25) - 1);
        return 0x14000000u | (unchecked((uint)immediate) & 0x03FFFFFFu);
    }

    private static uint EncodeArm64ConditionalBranch(
        ulong instructionAddress,
        ulong targetAddress,
        int condition)
    {
        long delta = checked((long)targetAddress - (long)instructionAddress);
        Assert.Equal(0, delta & 3);
        Assert.InRange(condition, 0, 15);
        long immediate = delta >> 2;
        Assert.InRange(immediate, -(1L << 18), (1L << 18) - 1);
        return 0x54000000u
               | (unchecked((uint)immediate) & 0x7FFFFu) << 5
               | checked((uint)condition);
    }

    private static uint EncodeArm64Adrp(ulong instructionAddress, ulong targetAddress, int register)
    {
        long instructionPage = checked((long)(instructionAddress & ~0xFFFUL));
        long targetPage = checked((long)(targetAddress & ~0xFFFUL));
        long immediate = (targetPage - instructionPage) >> 12;
        Assert.InRange(immediate, -(1L << 20), (1L << 20) - 1);
        uint encoded = unchecked((uint)immediate) & 0x1FFFFFu;
        return 0x90000000u
               | ((encoded & 3u) << 29)
               | (((encoded >> 2) & 0x7FFFFu) << 5)
               | checked((uint)register);
    }

    private static uint EncodeArm64AddAddress(ulong targetAddress, int register)
    {
        uint immediate = checked((uint)(targetAddress & 0xFFFUL));
        uint encodedRegister = checked((uint)register);
        return 0x91000000u
               | (immediate << 10)
               | (encodedRegister << 5)
               | encodedRegister;
    }

    private static uint EncodeArm64Move(int destinationRegister, int sourceRegister)
    {
        return 0xAA0003E0u
               | (checked((uint)sourceRegister) << 16)
               | checked((uint)destinationRegister);
    }

    private static void WriteArm64Instruction(
        Span<byte> image,
        int codeOffset,
        int instructionOffset,
        uint instruction)
    {
        WriteUInt32(image, codeOffset + instructionOffset, instruction);
    }

    private static void WriteProgramHeader(
        Span<byte> image,
        int offset,
        bool is64Bit,
        int fileOffset,
        ulong virtualAddress,
        int fileSize,
        uint flags)
    {
        WriteUInt32(image, offset, 1);
        if (is64Bit)
        {
            WriteUInt32(image, offset + 4, flags);
            WriteUInt64(image, offset + 8, checked((ulong)fileOffset));
            WriteUInt64(image, offset + 16, virtualAddress);
            WriteUInt64(image, offset + 24, virtualAddress);
            WriteUInt64(image, offset + 32, checked((ulong)fileSize));
            WriteUInt64(image, offset + 40, checked((ulong)fileSize));
            WriteUInt64(image, offset + 48, 0x1000);
        }
        else
        {
            WriteUInt32(image, offset + 4, checked((uint)fileOffset));
            WriteUInt32(image, offset + 8, checked((uint)virtualAddress));
            WriteUInt32(image, offset + 12, checked((uint)virtualAddress));
            WriteUInt32(image, offset + 16, checked((uint)fileSize));
            WriteUInt32(image, offset + 20, checked((uint)fileSize));
            WriteUInt32(image, offset + 24, flags);
            WriteUInt32(image, offset + 28, 0x1000);
        }
    }

    private static ulong WriteString(
        Span<byte> image,
        ulong dataAddress,
        int dataOffset,
        ref int stringOffset,
        string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        bytes.CopyTo(image.Slice(stringOffset, bytes.Length));
        image[stringOffset + bytes.Length] = 0;
        ulong address = dataAddress + checked((ulong)(stringOffset - dataOffset));
        stringOffset += bytes.Length + 1;
        return address;
    }

    private static void WritePointer(Span<byte> image, int offset, int pointerSize, ulong value)
    {
        if (pointerSize == 8)
            WriteUInt64(image, offset, value);
        else
            WriteUInt32(image, offset, checked((uint)value));
    }

    private static void WriteUInt16(Span<byte> image, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(image.Slice(offset, 2), value);
    }

    private static void WriteUInt32(Span<byte> image, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(image.Slice(offset, 4), value);
    }

    private static void WriteUInt64(Span<byte> image, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(image.Slice(offset, 8), value);
    }
}
