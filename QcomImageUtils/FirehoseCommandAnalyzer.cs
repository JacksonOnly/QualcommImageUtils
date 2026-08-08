using System.Buffers.Binary;
using System.Collections.Generic;
using QcomImageUtils.Models;
using QcomImageUtils.Types;
using QcomImageUtils.Utilities;
using ElfImage = QcomImageUtils.Utilities.ArmExecutableImage;
using ElfSegment = QcomImageUtils.Utilities.ArmExecutableSegment;

namespace QcomImageUtils;

/// <summary>
/// 通过 ELF/SBL MBN 映射、命令表结构、ARM 数据流和调度语义静态分析 Firehose 输入命令。
/// </summary>
public sealed class FirehoseCommandAnalyzer : IFirehoseCommandAnalyzer
{
    private static readonly byte[] ElfMagic = { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
    private static readonly byte[] SupportedFunctionsText = GetAsciiBytes("Supported Functions");
    private static readonly byte[] SupportedFunctionsFormatText = GetAsciiBytes("Supported Functions (%d):");
    private static readonly byte[] CallingHandlerText = GetAsciiBytes("Calling handler");

    private static readonly HashSet<string> KnownCommandNames = new(StringComparer.Ordinal)
    {
        "program",
        "read",
        "nop",
        "patch",
        "configure",
        "setbootablestoragedrive",
        "erase",
        "power",
        "quick_reset",
        "firmwarewrite",
        "getstorageinfo",
        "benchmark",
        "peek",
        "poke",
        "emmc",
        "ufs",
        "fixgpt",
        "getsha256digest",
    };

    private static readonly HashSet<string> CoreCommandNames = new(StringComparer.Ordinal)
    {
        "program",
        "read",
        "nop",
        "patch",
        "configure",
        "erase"
    };

    private const uint ExecutableFlag = ArmExecutableImageReader.ExecutableFlag;
    private const ushort ArmMachine = ArmExecutableImageReader.ArmMachine;
    private const ushort Arm64Machine = ArmExecutableImageReader.Arm64Machine;
    private const int MaximumDiagnosticLength = 512;
    private const int MaximumDiagnosticCount = 4096;
    private const int MaximumTrackedLiteralCount = 131072;
    private const int MaximumTagValueLifetime = 256;
    private const int MaximumFunctionInstructionCount = 16384;
    private const int MaximumFunctionEntryScanInstructionCount = 16 * 1024 * 1024;
    private const int MaximumFunctionEntryCount = 131072;
    private const ulong MaximumIntraFunctionBranchDistance = 0x1000;
    private const int MaximumArm32LookaheadInstructions = 8;
    private const int MaximumArm32DispatchEvidenceInstructions = 4;
    private const int MaximumArm32GetterLength = 64;
    private const int MaximumPackedCommandCount = 128;
    private const int InlineCommandNameFieldSize = 32;
    private const ulong MaximumArm32CandidateGap = 0x200;
    private const ulong UnknownAddress = ulong.MaxValue;

    private readonly int _maximumImageSize;
    private readonly int _maximumElfCount;
    private readonly int _minimumCommandTableEntries;
    private readonly int _maximumCommandLength;

    public FirehoseCommandAnalyzer(FirehoseCommandAnalyzerOptions? options = null)
    {
        options ??= new FirehoseCommandAnalyzerOptions();
        if (options.MaximumImageSize < 1)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumImageSize));
        if (options.MaximumElfCount is < 1 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumElfCount));
        if (options.MinimumCommandTableEntries is < 2 or > 128)
            throw new ArgumentOutOfRangeException(nameof(options.MinimumCommandTableEntries));
        if (options.MaximumCommandLength is < 8 or > 256)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumCommandLength));

        _maximumImageSize = options.MaximumImageSize;
        _maximumElfCount = options.MaximumElfCount;
        _minimumCommandTableEntries = options.MinimumCommandTableEntries;
        _maximumCommandLength = options.MaximumCommandLength;
    }

    public bool TryAnalyze(string filePath, out FirehoseCommandAnalysisResult result)
    {
        result = new FirehoseCommandAnalysisResult();
        if (!ImageFileReader.TryRead(
                filePath,
                _maximumImageSize,
                out byte[] image,
                out string fullPath,
                out string fileName,
                out string error))
        {
            result.OriginalFilePath = fullPath;
            result.OriginalFileName = fileName;
            return Complete(result, false, error);
        }

        bool success = TryAnalyze(image, out result);
        result.OriginalFilePath = fullPath;
        result.OriginalFileName = fileName;
        return success;
    }

    public bool TryAnalyze(ReadOnlySpan<byte> image, out FirehoseCommandAnalysisResult result)
    {
        result = new FirehoseCommandAnalysisResult();
        if (image.IsEmpty)
            return Complete(result, false, "镜像数据为空");
        if (image.Length > _maximumImageSize)
            return Complete(result, false, $"镜像数据超过配置的 {_maximumImageSize} 字节上限");

        try
        {
            var elfImages = new List<ElfImage>();
            int searchOffset = 0;
            while (searchOffset <= image.Length - ElfMagic.Length)
            {
                int relativeOffset = image.Slice(searchOffset).IndexOf(ElfMagic);
                if (relativeOffset < 0)
                    break;

                int elfOffset = searchOffset + relativeOffset;
                if (ArmExecutableImageReader.TryReadElf(image, elfOffset, out ElfImage elfImage)
                    && elfImage.Machine is ArmMachine or Arm64Machine)
                {
                    if (elfImages.Count >= _maximumElfCount)
                        return Complete(result, false, $"有效 ELF 数量超过配置的 {_maximumElfCount} 个上限");
                    elfImages.Add(elfImage);
                }

                searchOffset = elfOffset + ElfMagic.Length;
            }

            if (elfImages.Count == 0
                && ArmExecutableImageReader.TryReadSblMbn(image, out ElfImage mbnImage))
                elfImages.Add(mbnImage);

            result.AnalyzedElfCount = elfImages.Count;
            if (elfImages.Count == 0)
                return Complete(result, false, "未识别到有效的小端 ARM ELF32/ELF64 或 SBL MBN 镜像");

            var commands = new List<FirehoseCommandInfo>();
            var commandNames = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < elfImages.Count; index++)
            {
                ElfImage elfImage = elfImages[index];
                if (FirehosePayloadSizeAnalyzer.TryAnalyze(
                        image,
                        elfImage,
                        out ulong supportedPayloadSize)
                    && (!result.MaxPayloadSizeToTargetInBytesSupported.HasValue
                        || supportedPayloadSize
                        > result.MaxPayloadSizeToTargetInBytesSupported.Value))
                {
                    result.MaxPayloadSizeToTargetInBytesSupported = supportedPayloadSize;
                }

                CommandTable? commandTable = FindBestCommandTable(image, elfImage);
                var tableNames = new HashSet<string>(StringComparer.Ordinal);
                if (commandTable is not null)
                {
                    for (int entryIndex = 0; entryIndex < commandTable.Entries.Count; entryIndex++)
                    {
                        TableEntry entry = commandTable.Entries[entryIndex];
                        tableNames.Add(entry.Name);
                        if (!commandNames.Add(entry.Name))
                            continue;

                        commands.Add(new FirehoseCommandInfo
                        {
                            Name = entry.Name,
                            Source = FirehoseCommandSource.CommandTable,
                            ElfImageOffset = elfImage.ImageOffset,
                            TableEntryAddress = entry.EntryAddress,
                            HandlerAddress = entry.HandlerAddress
                        });
                    }
                }

                AddInlineCommands(
                    image,
                    elfImage,
                    commandTable,
                    tableNames,
                    commandNames,
                    commands);
            }

            if (commands.Count == 0
                && !result.MaxPayloadSizeToTargetInBytesSupported.HasValue)
                return Complete(result, false, "未发现可信的 Firehose 命令表");

            result.Commands = commands;
            return Complete(result, true, null);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return Complete(result, false, $"分析 Firehose 命令失败: {exception.Message}");
        }
    }

    private CommandTable? FindBestCommandTable(ReadOnlySpan<byte> image, ElfImage elfImage)
    {
        CommandTableHint? hint = FindCommandTableHint(image, elfImage);
        if (hint is not null)
        {
            return new CommandTable(
                hint.Entries,
                hint.StartAddress,
                hint.EntrySize,
                hasDeclaredCount: true);
        }

        bool hasSupportedFunctionsText = ContainsAscii(image, elfImage, SupportedFunctionsText);
        bool hasCallingHandlerText = ContainsAscii(image, elfImage, CallingHandlerText);
        CommandTable? best = null;
        int pointerEntrySize = elfImage.PointerSize * 2;
        int inlineEntrySize = InlineCommandNameFieldSize + elfImage.PointerSize;

        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            best = SelectLongerTable(
                best,
                ScanCommandTable(
                    image,
                    elfImage,
                    segment,
                    pointerEntrySize,
                    hasSupportedFunctionsText,
                    hasCallingHandlerText,
                    inlineNames: false));
            best = SelectLongerTable(
                best,
                ScanCommandTable(
                    image,
                    elfImage,
                    segment,
                    inlineEntrySize,
                    hasSupportedFunctionsText,
                    hasCallingHandlerText,
                    inlineNames: true));
        }

        return best;
    }

    private CommandTable? ScanCommandTable(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        int entrySize,
        bool hasSupportedFunctionsText,
        bool hasCallingHandlerText,
        bool inlineNames)
    {
        if (entrySize <= 0
            || segment.FileSize < (ulong)entrySize * (ulong)_minimumCommandTableEntries)
            return null;

        ulong alignment = (ulong)elfImage.PointerSize;
        ulong localOffset = (alignment - segment.VirtualAddress % alignment) % alignment;
        CommandTable? best = null;
        while (localOffset + (ulong)entrySize <= segment.FileSize)
        {
            List<TableEntry>? entries = null;
            ulong entryOffset = localOffset;
            while (entryOffset + (ulong)entrySize <= segment.FileSize)
            {
                if (!TryReadCommandTableEntry(
                        image,
                        elfImage,
                        segment,
                        entryOffset,
                        inlineNames,
                        out TableEntry entry))
                    break;

                entries ??= new List<TableEntry>();
                entries.Add(entry);
                entryOffset += (ulong)entrySize;
            }

            if (entries is not null
                && entries.Count >= _minimumCommandTableEntries
                && HasFirehoseTableSignature(
                    entries,
                    hasSupportedFunctionsText,
                    hasCallingHandlerText))
            {
                CommandTable candidate = new(
                    entries,
                    entries[0].EntryAddress,
                    entrySize,
                    hasDeclaredCount: false);
                best = SelectLongerTable(best, candidate);
            }

            localOffset += entries is not null
                ? (ulong)entries.Count * (ulong)entrySize
                : alignment;
        }

        return best;
    }

    private bool TryReadCommandTableAt(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong startAddress,
        int entrySize,
        int expectedCount,
        out List<TableEntry> entries)
    {
        entries = null!;
        if (expectedCount < _minimumCommandTableEntries
            || expectedCount > MaximumPackedCommandCount
            || (entrySize != elfImage.PointerSize * 2
                && entrySize != InlineCommandNameFieldSize + elfImage.PointerSize))
        {
            return false;
        }

        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if (startAddress < segment.VirtualAddress)
                continue;
            ulong localOffset = startAddress - segment.VirtualAddress;
            if (localOffset >= segment.FileSize
                || localOffset + (ulong)entrySize * (ulong)expectedCount > segment.FileSize)
            {
                continue;
            }

            bool inlineNames = entrySize == InlineCommandNameFieldSize + elfImage.PointerSize;
            var candidate = new List<TableEntry>(expectedCount);
            bool valid = true;
            for (int index = 0; index < expectedCount; index++)
            {
                ulong entryOffset = localOffset + (ulong)index * (ulong)entrySize;
                if (!TryReadCommandTableEntry(
                        image,
                        elfImage,
                        segment,
                        entryOffset,
                        inlineNames,
                        out TableEntry entry))
                {
                    valid = false;
                    break;
                }

                candidate.Add(entry);
            }

            if (valid)
            {
                entries = candidate;
                return true;
            }
        }

        return false;
    }

    private static CommandTable? SelectLongerTable(
        CommandTable? current,
        CommandTable? candidate)
    {
        if (candidate is null)
            return current;
        if (current is null || candidate.Entries.Count > current.Entries.Count)
            return candidate;
        return current;
    }

    private CommandTableHint? FindCommandTableHint(ReadOnlySpan<byte> image, ElfImage elfImage)
    {
        var literalAddresses = new List<ulong>();
        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            if (literalAddresses.Count >= MaximumTrackedLiteralCount)
                break;

            ElfSegment segment = elfImage.Segments[segmentIndex];
            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            int searchOffset = 0;
            while (searchOffset <= data.Length - SupportedFunctionsFormatText.Length)
            {
                int relative = data.Slice(searchOffset).IndexOf(SupportedFunctionsFormatText);
                if (relative < 0)
                    break;
                ulong literalAddress = segment.VirtualAddress + checked((ulong)(searchOffset + relative));
                literalAddresses.Add(literalAddress);
                if (literalAddresses.Count >= MaximumTrackedLiteralCount)
                    break;
                searchOffset += relative + SupportedFunctionsFormatText.Length;
            }
        }

        if (elfImage.Machine == Arm64Machine)
            return FindArm64CommandTableHint(image, elfImage, literalAddresses);
        if (elfImage.Machine == ArmMachine)
            return FindArm32CommandTableHint(image, elfImage, literalAddresses);
        return null;
    }

    private CommandTableHint? FindArm32CommandTableHint(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        List<ulong> supportedFunctionLiterals)
    {
        if (supportedFunctionLiterals.Count == 0)
            return null;

        var supportedSet = new HashSet<ulong>(supportedFunctionLiterals);
        CommandTableHint? bestHint = null;
        bool hasAmbiguousBestHint = false;
        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if ((segment.Flags & ExecutableFlag) == 0)
                continue;

            var addresses = new ulong[16];
            ResetTrackedAddresses(addresses);
            var constants = new int?[16];
            var evidence = new CommandTableEvidenceWindow();
            HashSet<ulong> functionEntries = CollectArm32FunctionEntries(image, segment);
            int ordinal = 0;
            int functionInstructionCount = 0;
            for (ulong offset = (4 - (segment.VirtualAddress & 3)) & 3;
                 offset + 4 <= segment.FileSize;
                 offset += 4)
            {
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)(segment.FileOffset + offset)), 4));
                ulong instructionAddress = segment.VirtualAddress + offset;
                if (functionInstructionCount > 0
                    && functionEntries.Contains(instructionAddress))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetTrackedAddresses(addresses);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }
                ordinal++;
                functionInstructionCount++;

                if (evidence.IsExpired(ordinal, 256))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                }

                bool hasImmediateAddress = ArmInstructionDecoder.TryDecodeArm32ImmediateAddress(
                    instruction,
                    instructionAddress,
                    out int immediateDestination,
                    out int immediateSource,
                    out int immediateOpcode,
                    out uint immediateValue);
                if (evidence.IsActive
                    && TryDecodeArm32TableStride(
                        instruction,
                        instructionAddress,
                        out int strideRegister,
                        out int stride)
                    && addresses[strideRegister] != UnknownAddress)
                {
                    evidence.AddTraversal(
                        addresses[strideRegister],
                        stride);
                }

                ulong? resolvedAddress = null;
                int? movedCount = null;
                int? comparedCount = null;
                if (TryDecodeArmAddress(
                        image,
                        elfImage,
                        instruction,
                        instructionAddress,
                        out int addressRegister,
                        out ulong address))
                {
                    addresses[addressRegister] = address;
                    constants[addressRegister] = null;
                    resolvedAddress = address;
                }
                else if (ArmInstructionDecoder.TryDecodeArm32MoveImmediate(
                             instruction,
                             out int moveRegister,
                             out uint moveImmediate))
                {
                    addresses[moveRegister] = moveImmediate;
                    constants[moveRegister] = moveImmediate <= int.MaxValue
                        ? checked((int)moveImmediate)
                        : null;
                    resolvedAddress = moveImmediate;
                    movedCount = constants[moveRegister];
                }
                else if (ArmInstructionDecoder.TryDecodeArm32MoveWide(
                             instruction,
                             out int moveWideRegister,
                             out uint moveWideImmediate,
                             out bool isHighHalf))
                {
                    ulong currentAddress = addresses[moveWideRegister];
                    ulong moveWideAddress = isHighHalf
                        && currentAddress != UnknownAddress
                        ? (currentAddress & 0xFFFFUL) | ((ulong)moveWideImmediate << 16)
                        : isHighHalf ? UnknownAddress : moveWideImmediate;
                    addresses[moveWideRegister] = moveWideAddress;
                    int? currentConstant = constants[moveWideRegister];
                    constants[moveWideRegister] = isHighHalf
                        && currentConstant.HasValue
                        ? (currentConstant.Value & 0xFFFF)
                          | checked((int)moveWideImmediate << 16)
                        : isHighHalf ? null : checked((int)moveWideImmediate);
                    if (moveWideAddress != UnknownAddress)
                        resolvedAddress = moveWideAddress;
                    if (constants[moveWideRegister] is int constantValue)
                        movedCount = constantValue;
                }
                else if (ArmInstructionDecoder.TryDecodeArm32CompareImmediate(
                             instruction,
                             out _,
                             out uint compareImmediate))
                {
                    if (compareImmediate <= int.MaxValue)
                        comparedCount = checked((int)compareImmediate);
                }
                else if (ArmInstructionDecoder.TryDecodeArm32Move(
                             instruction,
                             out int moveDestination,
                             out int moveSource))
                {
                    addresses[moveDestination] = addresses[moveSource];
                    constants[moveDestination] = constants[moveSource];
                    if (addresses[moveDestination] != UnknownAddress)
                        resolvedAddress = addresses[moveDestination];
                }
                else if (hasImmediateAddress
                         && addresses[immediateSource] != UnknownAddress
                         && TryApplyAddressImmediate(
                             addresses[immediateSource],
                             immediateOpcode,
                             immediateValue,
                             out ulong immediateAddress))
                {
                    addresses[immediateDestination] = immediateAddress;
                    constants[immediateDestination] = null;
                    resolvedAddress = immediateAddress;
                }
                else if (ArmInstructionDecoder.IsArm32Call(instruction))
                {
                    CaptureAdvertisedCounts(
                        supportedSet,
                        addresses,
                        constants,
                        4,
                        evidence);
                    InvalidateArm32CallerSavedAddresses(addresses);
                    InvalidateArm32CallerSavedConstants(constants);
                }
                else
                {
                    for (int register = 0; register < addresses.Length; register++)
                    {
                        if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                        {
                            addresses[register] = UnknownAddress;
                            constants[register] = null;
                        }
                    }
                }

                if (resolvedAddress is ulong resolved
                    && supportedSet.Contains(resolved))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Start(ordinal);
                }
                else if (evidence.IsActive && resolvedAddress is ulong tableAddress)
                {
                    evidence.AddTableAddress(tableAddress);
                }

                if (evidence.IsActive && movedCount is int moveCount)
                    evidence.AddMoveCount(moveCount, _minimumCommandTableEntries);
                if (evidence.IsActive && comparedCount is int compareCount)
                    evidence.AddCompareCount(compareCount, _minimumCommandTableEntries);

                if (IsArm32FunctionBoundary(
                        instruction,
                        instructionAddress,
                        segment,
                        functionEntries)
                    || functionInstructionCount >= MaximumFunctionInstructionCount)
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetTrackedAddresses(addresses);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }
            }

            CommitCommandTableEvidence(
                image,
                elfImage,
                evidence,
                ref bestHint,
                ref hasAmbiguousBestHint);
        }

        CommandTableHint? armHint = bestHint;
        bool hasAmbiguousArmHint = hasAmbiguousBestHint;
        CommandTableHint? thumbHint = FindThumbCommandTableHint(
            image,
            elfImage,
            supportedSet,
            out bool hasAmbiguousThumbHint);
        return SelectUnambiguousHint(
            armHint,
            hasAmbiguousArmHint,
            thumbHint,
            hasAmbiguousThumbHint);
    }

    private CommandTableHint? FindThumbCommandTableHint(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        HashSet<ulong> supportedFunctionLiterals,
        out bool hasAmbiguousBestHint)
    {
        CommandTableHint? bestHint = null;
        hasAmbiguousBestHint = false;
        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if ((segment.Flags & ExecutableFlag) == 0)
                continue;

            var addresses = new ulong[16];
            ResetTrackedAddresses(addresses);
            var constants = new int?[16];
            var evidence = new CommandTableEvidenceWindow();
            HashSet<ulong> functionEntries = CollectThumbFunctionEntries(image, segment);
            int ordinal = 0;
            int functionInstructionCount = 0;
            ulong offset = (2 - (segment.VirtualAddress & 1)) & 1;
            while (TryReadThumbInstruction(
                       image,
                       segment,
                       offset,
                       out ushort first,
                       out ushort second,
                       out int instructionSize))
            {
                ulong instructionAddress = segment.VirtualAddress + offset;
                if (functionInstructionCount > 0
                    && functionEntries.Contains(instructionAddress))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetTrackedAddresses(addresses);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }
                ordinal++;
                functionInstructionCount++;

                if (evidence.IsExpired(ordinal, 256))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                }

                if (evidence.IsActive
                    && TryDecodeThumbTableStride(
                        first,
                        out int strideRegister,
                        out int stride)
                    && addresses[strideRegister] != UnknownAddress)
                {
                    evidence.AddTraversal(addresses[strideRegister], stride);
                }

                ulong? resolvedAddress = null;
                int? movedCount = null;
                int? comparedCount = null;
                if (TryDecodeThumbAddress(
                        image,
                        elfImage,
                        segment,
                        offset,
                        instructionAddress,
                        first,
                        out int addressRegister,
                        out ulong address,
                        out _))
                {
                    addresses[addressRegister] = address;
                    constants[addressRegister] = null;
                    resolvedAddress = address;
                }
                else if ((first & 0xF800) == 0x2000)
                {
                    int register = (first >> 8) & 7;
                    addresses[register] = (uint)(first & 0xFF);
                    constants[register] = first & 0xFF;
                    resolvedAddress = addresses[register];
                    movedCount = first & 0xFF;
                }
                else if ((first & 0xF800) == 0x2800)
                {
                    comparedCount = first & 0xFF;
                }
                else if (ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
                             first,
                             second,
                             out int moveImmediateRegister,
                             out uint moveImmediate))
                {
                    addresses[moveImmediateRegister] = moveImmediate;
                    constants[moveImmediateRegister] = moveImmediate <= int.MaxValue
                        ? checked((int)moveImmediate)
                        : null;
                    resolvedAddress = moveImmediate;
                    movedCount = constants[moveImmediateRegister];
                }
                else if (ArmInstructionDecoder.TryDecodeThumbAddSubtractImmediate(
                             first,
                             second,
                             out int arithmeticDestination,
                             out int arithmeticSource,
                             out uint arithmeticImmediate,
                             out bool subtracts))
                {
                    if (arithmeticDestination == 15)
                    {
                        if (subtracts && (first & 0x10) != 0
                            && arithmeticImmediate <= int.MaxValue)
                        {
                            comparedCount = checked((int)arithmeticImmediate);
                        }
                    }
                    else
                    {
                        ulong sourceAddress = addresses[arithmeticSource];
                        if (sourceAddress != UnknownAddress
                            && (subtracts
                                ? sourceAddress >= arithmeticImmediate
                                : sourceAddress <= ulong.MaxValue - arithmeticImmediate))
                        {
                            ulong arithmeticAddress = subtracts
                                ? sourceAddress - arithmeticImmediate
                                : sourceAddress + arithmeticImmediate;
                            addresses[arithmeticDestination] = arithmeticAddress;
                            resolvedAddress = arithmeticAddress;
                        }
                        else
                        {
                            addresses[arithmeticDestination] = UnknownAddress;
                        }

                        int? sourceConstant = constants[arithmeticSource];
                        if (sourceConstant.HasValue
                            && arithmeticImmediate <= int.MaxValue
                            && (subtracts
                                ? sourceConstant.Value >= checked((int)arithmeticImmediate)
                                : sourceConstant.Value
                                  <= int.MaxValue - checked((int)arithmeticImmediate)))
                        {
                            constants[arithmeticDestination] = subtracts
                                ? sourceConstant.Value - checked((int)arithmeticImmediate)
                                : sourceConstant.Value + checked((int)arithmeticImmediate);
                        }
                        else
                        {
                            constants[arithmeticDestination] = null;
                        }
                    }
                }
                else if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                             first,
                             second,
                             out int moveWideRegister,
                             out uint moveWideImmediate,
                             out bool isHighHalf))
                {
                    ulong currentAddress = addresses[moveWideRegister];
                    ulong moveWideAddress = isHighHalf
                        && currentAddress != UnknownAddress
                        ? (currentAddress & 0xFFFFUL) | ((ulong)moveWideImmediate << 16)
                        : isHighHalf ? UnknownAddress : moveWideImmediate;
                    addresses[moveWideRegister] = moveWideAddress;
                    int? currentConstant = constants[moveWideRegister];
                    constants[moveWideRegister] = isHighHalf
                        && currentConstant.HasValue
                        ? (currentConstant.Value & 0xFFFF)
                          | checked((int)moveWideImmediate << 16)
                        : isHighHalf ? null : checked((int)moveWideImmediate);
                    if (moveWideAddress != UnknownAddress)
                        resolvedAddress = moveWideAddress;
                    if (constants[moveWideRegister] is int constantValue)
                        movedCount = constantValue;
                }
                else if (ArmInstructionDecoder.TryDecodeThumbMove(
                             first,
                             out int destination,
                             out int source))
                {
                    addresses[destination] = addresses[source];
                    constants[destination] = constants[source];
                    if (addresses[destination] != UnknownAddress)
                        resolvedAddress = addresses[destination];
                }
                else if (ArmInstructionDecoder.IsThumbRegisterCall(first)
                         || ArmInstructionDecoder.IsThumbBranchLink(first, second))
                {
                    CaptureAdvertisedCounts(
                        supportedFunctionLiterals,
                        addresses,
                        constants,
                        4,
                        evidence);
                    InvalidateArm32CallerSavedAddresses(addresses);
                    InvalidateArm32CallerSavedConstants(constants);
                }
                else
                {
                    for (int register = 0; register < addresses.Length; register++)
                    {
                        if (ArmInstructionDecoder.ThumbWritesRegister(
                                first,
                                second,
                                instructionSize,
                                register))
                        {
                            addresses[register] = UnknownAddress;
                            constants[register] = null;
                        }
                    }
                }

                if (resolvedAddress is ulong resolved
                    && supportedFunctionLiterals.Contains(resolved))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Start(ordinal);
                }
                else if (evidence.IsActive && resolvedAddress is ulong tableAddress)
                {
                    evidence.AddTableAddress(tableAddress);
                }

                if (evidence.IsActive && movedCount is int moveCount)
                    evidence.AddMoveCount(moveCount, _minimumCommandTableEntries);
                if (evidence.IsActive && comparedCount is int compareCount)
                    evidence.AddCompareCount(compareCount, _minimumCommandTableEntries);

                if (IsThumbFunctionBoundary(
                        first,
                        second,
                        instructionSize,
                        instructionAddress,
                        segment,
                        functionEntries)
                    || functionInstructionCount >= MaximumFunctionInstructionCount)
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetTrackedAddresses(addresses);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }

                offset += checked((ulong)instructionSize);
            }

            CommitCommandTableEvidence(
                image,
                elfImage,
                evidence,
                ref bestHint,
                ref hasAmbiguousBestHint);
        }

        return bestHint;
    }

    private static CommandTableHint? SelectUnambiguousHint(
        CommandTableHint? first,
        bool isFirstAmbiguous,
        CommandTableHint? second,
        bool isSecondAmbiguous)
    {
        if (second is null)
            return isFirstAmbiguous ? null : first;
        if (first is null)
            return isSecondAmbiguous ? null : second;
        if (IsStrongerEvidence(first.EvidenceStrength, second.EvidenceStrength))
            return isFirstAmbiguous ? null : first;
        if (IsStrongerEvidence(second.EvidenceStrength, first.EvidenceStrength))
            return isSecondAmbiguous ? null : second;
        if (isFirstAmbiguous || isSecondAmbiguous)
            return null;
        return first.HasSameTable(second) ? first : null;
    }

    private static bool IsStrongerEvidence(
        CommandTableEvidenceStrength candidate,
        CommandTableEvidenceStrength current)
    {
        return candidate switch
        {
            CommandTableEvidenceStrength.AdvertisedCountAndBoundTraversal =>
                current is not CommandTableEvidenceStrength.AdvertisedCountAndBoundTraversal,
            CommandTableEvidenceStrength.BoundTraversal =>
                current is CommandTableEvidenceStrength.AdvertisedCount
                    or CommandTableEvidenceStrength.NearAnchor,
            CommandTableEvidenceStrength.AdvertisedCount =>
                current is CommandTableEvidenceStrength.NearAnchor,
            _ => false
        };
    }

    private static void ResetTrackedAddresses(ulong[] addresses)
    {
        for (int register = 0; register < addresses.Length; register++)
            addresses[register] = UnknownAddress;
    }

    private static void InvalidateArm32CallerSavedAddresses(ulong[] addresses)
    {
        for (int register = 0; register <= 3; register++)
            addresses[register] = UnknownAddress;
        addresses[12] = UnknownAddress;
        addresses[14] = UnknownAddress;
    }

    private static void InvalidateArm32CallerSavedConstants(int?[] constants)
    {
        for (int register = 0; register <= 3; register++)
            constants[register] = null;
        constants[12] = null;
        constants[14] = null;
    }

    private static void ResetArm32TrackedState(
        ulong[] targetAddresses,
        int[] tagOrigins)
    {
        ResetTrackedAddresses(targetAddresses);
        for (int register = 0; register < tagOrigins.Length; register++)
            tagOrigins[register] = -1;
    }

    private static void ClobberArm32CallRegisters(
        ulong[] targetAddresses,
        int[] tagOrigins)
    {
        for (int register = 0; register <= 3; register++)
            InvalidateArm32TrackedRegister(register, targetAddresses, tagOrigins);
        InvalidateArm32TrackedRegister(12, targetAddresses, tagOrigins);
        InvalidateArm32TrackedRegister(14, targetAddresses, tagOrigins);
    }

    private static void InvalidateArm32WrittenRegisters(
        uint instruction,
        ulong[] targetAddresses,
        int[] tagOrigins)
    {
        for (int register = 0; register < targetAddresses.Length; register++)
        {
            if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                InvalidateArm32TrackedRegister(register, targetAddresses, tagOrigins);
        }
    }

    private static void InvalidateThumbWrittenRegisters(
        ushort first,
        ushort second,
        int instructionSize,
        ulong[] targetAddresses,
        int[] tagOrigins)
    {
        for (int register = 0; register < targetAddresses.Length; register++)
        {
            if (ArmInstructionDecoder.ThumbWritesRegister(
                    first,
                    second,
                    instructionSize,
                    register))
            {
                InvalidateArm32TrackedRegister(register, targetAddresses, tagOrigins);
            }
        }
    }

    private static void InvalidateArm32TrackedRegister(
        int register,
        ulong[] targetAddresses,
        int[] tagOrigins)
    {
        targetAddresses[register] = UnknownAddress;
        tagOrigins[register] = -1;
    }

    private static bool TryApplyAddressImmediate(
        ulong sourceAddress,
        int opcode,
        uint immediate,
        out ulong address)
    {
        if (opcode == 4)
        {
            if (sourceAddress > ulong.MaxValue - immediate)
            {
                address = 0;
                return false;
            }

            address = sourceAddress + immediate;
            return true;
        }

        if (opcode == 2 && sourceAddress >= immediate)
        {
            address = sourceAddress - immediate;
            return true;
        }

        address = 0;
        return false;
    }

    private static bool TryDecodeThumbTableStride(
        ushort instruction,
        out int sourceRegister,
        out int stride)
    {
        ushort opcode = (ushort)(instruction & 0xF800);
        if (opcode is 0x3000 or 0x3800)
        {
            sourceRegister = (instruction >> 8) & 7;
            stride = instruction & 0xFF;
            return stride is >= 4 and <= 128;
        }

        ushort addSubtractOpcode = (ushort)(instruction & 0xFE00);
        if (addSubtractOpcode is 0x1C00 or 0x1E00)
        {
            sourceRegister = (instruction >> 3) & 7;
            int destinationRegister = instruction & 7;
            stride = (instruction >> 6) & 7;
            return destinationRegister == sourceRegister && stride >= 4;
        }

        sourceRegister = 0;
        stride = 0;
        return false;
    }

    private static bool TryDecodeArm32TableStride(
        uint instruction,
        ulong instructionAddress,
        out int sourceRegister,
        out int stride)
    {
        if (ArmInstructionDecoder.TryDecodeArm32ImmediateAddress(
                instruction,
                instructionAddress,
                out int destinationRegister,
                out sourceRegister,
                out _,
                out uint immediate)
            && destinationRegister == sourceRegister
            && immediate is >= 4 and <= 128)
        {
            stride = checked((int)immediate);
            return true;
        }

        bool isPostIndexedTransfer = (instruction >> 28) != 0xFu
                                     && (instruction & 0x0C000000u) == 0x04000000u
                                     && (instruction & 0x02000000u) == 0
                                     && (instruction & 0x01000000u) == 0;
        uint transferImmediate = instruction & 0xFFFu;
        if (isPostIndexedTransfer && transferImmediate is >= 4 and <= 128)
        {
            sourceRegister = (int)((instruction >> 16) & 0xFu);
            stride = checked((int)transferImmediate);
            return sourceRegister < 15;
        }

        sourceRegister = 0;
        stride = 0;
        return false;
    }

    private CommandTableHint? FindArm64CommandTableHint(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        List<ulong> supportedFunctionLiterals)
    {
        if (supportedFunctionLiterals.Count == 0)
            return null;

        var supportedSet = new HashSet<ulong>(supportedFunctionLiterals);
        CommandTableHint? bestHint = null;
        bool hasAmbiguousBestHint = false;

        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if ((segment.Flags & ExecutableFlag) == 0)
                continue;

            var addresses = new ulong[31];
            var tagOrigins = new int[31];
            ResetArm64Registers(addresses, tagOrigins);
            var constants = new int?[31];
            var evidence = new CommandTableEvidenceWindow();
            HashSet<ulong> functionEntries = CollectArm64FunctionEntries(image, segment);
            int ordinal = 0;
            int functionInstructionCount = 0;

            for (ulong offset = 0; offset + 4 <= segment.FileSize; offset += 4)
            {
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)(segment.FileOffset + offset)), 4));
                ulong instructionAddress = segment.VirtualAddress + offset;
                if (functionInstructionCount > 0
                    && functionEntries.Contains(instructionAddress))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetArm64Registers(addresses, tagOrigins);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }
                ordinal++;
                functionInstructionCount++;

                if (evidence.IsExpired(ordinal, 384))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                }

                if (evidence.IsActive
                    && TryDecodeArm64TableStride(
                        instruction,
                        out int strideSourceRegister,
                        out int stride)
                    && addresses[strideSourceRegister] != UnknownAddress)
                {
                    evidence.AddTraversal(
                        addresses[strideSourceRegister],
                        stride);
                }

                ulong? resolvedAddress = null;
                int? movedCount = null;
                int? comparedCount = null;
                if (TryDecodeArm64Address(
                        instruction,
                        instructionAddress,
                        out int addressRegister,
                        out ulong address,
                        out _))
                {
                    addresses[addressRegister] = address;
                    tagOrigins[addressRegister] = -1;
                    constants[addressRegister] = null;
                    resolvedAddress = address;
                }
                else if (TryDecodeArm64AddImmediate(
                             instruction,
                             addresses,
                             tagOrigins,
                             ordinal,
                             out int addRegister,
                             out ulong addAddress,
                             out _))
                {
                    addresses[addRegister] = addAddress;
                    tagOrigins[addRegister] = -1;
                    constants[addRegister] = null;
                    if (addAddress != UnknownAddress)
                        resolvedAddress = addAddress;
                }
                else if (TryDecodeArm64LiteralLoad(
                             image,
                             elfImage,
                             instruction,
                             instructionAddress,
                             out int literalRegister,
                             out ulong literalValue))
                {
                    addresses[literalRegister] = literalValue;
                    tagOrigins[literalRegister] = -1;
                    constants[literalRegister] = null;
                    resolvedAddress = literalValue;
                }
                else if (ArmInstructionDecoder.TryDecodeArm64MoveWide(
                             instruction,
                             out int constantRegister,
                             out ulong moveWideValue,
                             out ulong moveWideMask,
                             out bool keepsOtherBits))
                {
                    ulong currentAddress = addresses[constantRegister];
                    ulong moveWideAddress = keepsOtherBits
                        ? currentAddress == UnknownAddress
                            ? UnknownAddress
                            : (currentAddress & ~moveWideMask)
                              | (moveWideValue & moveWideMask)
                        : moveWideValue;
                    addresses[constantRegister] = moveWideAddress;
                    tagOrigins[constantRegister] = -1;
                    int? currentConstant = constants[constantRegister];
                    ulong? moveWideConstant = keepsOtherBits
                        ? currentConstant.HasValue
                            ? ((ulong)currentConstant.Value & ~moveWideMask)
                              | (moveWideValue & moveWideMask)
                            : null
                        : moveWideValue;
                    constants[constantRegister] = moveWideConstant.HasValue
                                                      && moveWideConstant.Value <= int.MaxValue
                        ? checked((int)moveWideConstant.Value)
                        : null;
                    if (moveWideAddress != UnknownAddress)
                        resolvedAddress = moveWideAddress;
                    movedCount = constants[constantRegister];
                }
                else if (ArmInstructionDecoder.TryDecodeArm64CompareImmediate(
                             instruction,
                             out _,
                             out int comparedValue))
                {
                    comparedCount = comparedValue;
                }
                else if (ArmInstructionDecoder.TryDecodeArm64Move(
                             instruction,
                             out int moveDestination,
                             out int moveSource))
                {
                    addresses[moveDestination] = addresses[moveSource];
                    tagOrigins[moveDestination] = -1;
                    constants[moveDestination] = constants[moveSource];
                    if (addresses[moveDestination] != UnknownAddress)
                        resolvedAddress = addresses[moveDestination];
                }
                else if (ArmInstructionDecoder.IsArm64Call(instruction))
                {
                    CaptureAdvertisedCounts(
                        supportedSet,
                        addresses,
                        constants,
                        8,
                        evidence);
                    ClobberArm64CallRegisters(addresses, tagOrigins);
                    for (int register = 0; register <= 17; register++)
                        constants[register] = null;
                }
                else
                {
                    for (int register = 0; register < addresses.Length; register++)
                    {
                        if (!ArmInstructionDecoder.Arm64WritesRegister(
                                instruction,
                                register))
                        {
                            continue;
                        }

                        InvalidateArm64Register(register, addresses, tagOrigins);
                        constants[register] = null;
                    }
                }

                if (resolvedAddress is ulong resolved
                    && supportedSet.Contains(resolved))
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Start(ordinal);
                }
                else if (evidence.IsActive && resolvedAddress is ulong tableAddress)
                {
                    evidence.AddTableAddress(tableAddress);
                }

                if (evidence.IsActive && movedCount is int moveValue)
                    evidence.AddMoveCount(moveValue, _minimumCommandTableEntries);
                if (evidence.IsActive && comparedCount is int compareValue)
                    evidence.AddCompareCount(compareValue, _minimumCommandTableEntries);

                if (IsArm64FunctionBoundary(
                        instruction,
                        instructionAddress,
                        segment,
                        functionEntries)
                    || functionInstructionCount >= MaximumFunctionInstructionCount)
                {
                    CommitCommandTableEvidence(
                        image,
                        elfImage,
                        evidence,
                        ref bestHint,
                        ref hasAmbiguousBestHint);
                    evidence.Reset();
                    ResetArm64Registers(addresses, tagOrigins);
                    Array.Clear(constants, 0, constants.Length);
                    functionInstructionCount = 0;
                }
            }

            CommitCommandTableEvidence(
                image,
                elfImage,
                evidence,
                ref bestHint,
                ref hasAmbiguousBestHint);
        }

        return hasAmbiguousBestHint ? null : bestHint;
    }

    private void CommitCommandTableEvidence(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        CommandTableEvidenceWindow evidence,
        ref CommandTableHint? bestHint,
        ref bool hasAmbiguousBestHint)
    {
        if (!evidence.IsActive)
            return;

        foreach (int count in evidence.CompareCounts)
        {
            if (count < _minimumCommandTableEntries || count > MaximumPackedCommandCount)
                continue;
            if (!evidence.MoveCounts.Contains(count))
                continue;

            foreach (ulong startAddress in evidence.TableAddresses)
            {
                ConsiderCommandTableLayout(
                    image,
                    elfImage,
                    evidence,
                    startAddress,
                    count,
                    elfImage.PointerSize * 2,
                    ref bestHint,
                    ref hasAmbiguousBestHint);
                ConsiderCommandTableLayout(
                    image,
                    elfImage,
                    evidence,
                    startAddress,
                    count,
                    InlineCommandNameFieldSize + elfImage.PointerSize,
                    ref bestHint,
                    ref hasAmbiguousBestHint);
            }
        }
    }

    private void ConsiderCommandTableLayout(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        CommandTableEvidenceWindow evidence,
        ulong startAddress,
        int count,
        int entrySize,
        ref CommandTableHint? bestHint,
        ref bool hasAmbiguousBestHint)
    {
        if (!TryReadCommandTableAt(
                image,
                elfImage,
                startAddress,
                entrySize,
                count,
                out List<TableEntry> entries)
            || !HasFirehoseTableSignature(
                entries,
                hasSupportedFunctionsText: true,
                hasCallingHandlerText: false))
        {
            return;
        }

        bool hasBoundTraversal = evidence.HasTraversal(startAddress, entrySize);
        bool hasAdvertisedCount = evidence.AdvertisedCounts.Contains(count);
        CommandTableEvidenceStrength strength = hasBoundTraversal
            ? hasAdvertisedCount
                ? CommandTableEvidenceStrength.AdvertisedCountAndBoundTraversal
                : CommandTableEvidenceStrength.BoundTraversal
            : hasAdvertisedCount
                ? CommandTableEvidenceStrength.AdvertisedCount
                : CommandTableEvidenceStrength.NearAnchor;
        var candidate = new CommandTableHint(
            entries,
            startAddress,
            entrySize,
            strength);
        if (bestHint is null
            || IsStrongerEvidence(candidate.EvidenceStrength, bestHint.EvidenceStrength))
        {
            bestHint = candidate;
            hasAmbiguousBestHint = false;
            return;
        }
        if (IsStrongerEvidence(bestHint.EvidenceStrength, candidate.EvidenceStrength)
            || bestHint.HasSameTable(candidate))
        {
            return;
        }

        hasAmbiguousBestHint = true;
    }

    private void CaptureAdvertisedCounts(
        HashSet<ulong> supportedFunctionLiterals,
        ulong[] addresses,
        int?[] constants,
        int argumentRegisterCount,
        CommandTableEvidenceWindow evidence)
    {
        if (!evidence.IsActive)
            return;

        bool hasSupportedFunctionArgument = false;
        for (int register = 0;
             register < argumentRegisterCount && register < addresses.Length;
             register++)
        {
            if (supportedFunctionLiterals.Contains(addresses[register]))
            {
                hasSupportedFunctionArgument = true;
                break;
            }
        }
        if (!hasSupportedFunctionArgument)
            return;

        for (int register = 0;
             register < argumentRegisterCount && register < constants.Length;
            register++)
        {
            if (constants[register] is int value)
                evidence.AddAdvertisedCount(value, _minimumCommandTableEntries);
        }
    }

    private static bool TryDecodeArm64TableStride(
        uint instruction,
        out int sourceRegister,
        out int immediate)
    {
        sourceRegister = 0;
        immediate = 0;
        if (ArmInstructionDecoder.TryDecodeArm64AddImmediate(
                instruction,
                out int destinationRegister,
                out sourceRegister,
                out ulong addImmediate,
                out bool is64Bit,
                out bool setsFlags)
            && is64Bit
            && !setsFlags
            && addImmediate <= int.MaxValue)
        {
            immediate = checked((int)addImmediate);
            return sourceRegister < 31
                   && destinationRegister == sourceRegister
                   && immediate is >= 4 and <= 128;
        }

        // Optimized dispatch loops commonly advance the table pointer with a
        // post-indexed LDR/STR (`ldr x2, [x21], #16`).
        if ((instruction & 0x3B200C00u) != 0x38000400u)
            return false;

        sourceRegister = (int)((instruction >> 5) & 0x1Fu);
        immediate = checked((int)ArmInstructionMath.SignExtend(
            (instruction >> 12) & 0x1FFu,
            9));
        immediate = Math.Abs(immediate);
        return sourceRegister < 31 && immediate is >= 4 and <= 128;
    }

    private bool TryReadCommandTableEntry(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment tableSegment,
        ulong localOffset,
        bool inlineNames,
        out TableEntry entry)
    {
        return inlineNames
            ? TryReadInlineNameTableEntry(image, elfImage, tableSegment, localOffset, out entry)
            : TryReadTableEntry(image, elfImage, tableSegment, localOffset, out entry);
    }

    private bool TryReadInlineNameTableEntry(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment tableSegment,
        ulong localOffset,
        out TableEntry entry)
    {
        entry = default;
        ulong fileOffset = tableSegment.FileOffset + localOffset;
        ReadOnlySpan<byte> nameField = image.Slice(
            checked((int)fileOffset),
            InlineCommandNameFieldSize);
        int terminator = nameField.IndexOf((byte)0);
        if (terminator < 2
            || terminator > _maximumCommandLength
            || !TryDecodeCommandName(nameField.Slice(0, terminator), out string commandName))
        {
            return false;
        }

        for (int index = terminator + 1; index < nameField.Length; index++)
        {
            if (nameField[index] != 0)
                return false;
        }

        if (!ArmExecutableImageReader.TryReadPointer(
                image,
                fileOffset + InlineCommandNameFieldSize,
                elfImage.PointerSize,
                out ulong handlerAddress)
            || !ArmExecutableImageReader.IsExecutableAddress(elfImage, handlerAddress)
            || localOffset > ulong.MaxValue - tableSegment.VirtualAddress)
        {
            return false;
        }

        entry = new TableEntry(
            commandName,
            tableSegment.VirtualAddress + localOffset,
            handlerAddress);
        return true;
    }

    private bool TryReadTableEntry(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment tableSegment,
        ulong localOffset,
        out TableEntry entry)
    {
        entry = default;
        ulong fileOffset = tableSegment.FileOffset + localOffset;
        if (!ArmExecutableImageReader.TryReadPointer(
                image,
                fileOffset,
                elfImage.PointerSize,
                out ulong nameAddress)
            || !ArmExecutableImageReader.TryReadPointer(
                image,
                fileOffset + (ulong)elfImage.PointerSize,
                elfImage.PointerSize,
                out ulong handlerAddress)
            || !TryReadCommandString(image, elfImage, nameAddress, out string commandName)
            || !ArmExecutableImageReader.IsExecutableAddress(elfImage, handlerAddress))
        {
            return false;
        }

        if (localOffset > ulong.MaxValue - tableSegment.VirtualAddress)
            return false;

        entry = new TableEntry(
            commandName,
            tableSegment.VirtualAddress + localOffset,
            handlerAddress);
        return true;
    }

    private void AddInlineCommands(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        CommandTable? commandTable,
        HashSet<string> tableNames,
        HashSet<string> commandNames,
        List<FirehoseCommandInfo> commands)
    {
        CollectAsciiStrings(
            image,
            elfImage,
            out HashSet<string> standalone,
            out Dictionary<ulong, string> literals,
            out List<string> diagnostics);

        var inlineNames = new List<string>();
        var inlineNameSet = new HashSet<string>(StringComparer.Ordinal);

        // A fixed table can be a deliberately truncated view of the dispatch
        // pool (some builds expose only the first few handlers). The
        // Calling-handler string anchors the complete pool, so inspect it
        // first and let code-based inline commands follow the advertised order.
        if (commandTable is null || !commandTable.HasDeclaredCount)
        {
            CollectPackedCommandPool(
                image,
                elfImage,
                inlineNameSet,
                inlineNames);
        }

        if (elfImage.Machine == Arm64Machine)
        {
            CollectArm64InlineCommands(
                image,
                elfImage,
                commandTable,
                tableNames,
                standalone,
                literals,
                inlineNameSet,
                inlineNames);
        }
        else if (elfImage.Machine == ArmMachine)
        {
            CollectArm32InlineCommands(
                image,
                elfImage,
                tableNames,
                standalone,
                literals,
                inlineNameSet,
                inlineNames);
        }

        if (commandTable is not null || inlineNames.Count > 0)
        {
            CollectDiagnosticInlineCommands(
                diagnostics,
                tableNames,
                standalone,
                inlineNameSet,
                inlineNames);
        }

        for (int index = 0; index < inlineNames.Count; index++)
        {
            string name = inlineNames[index];
            if (IsNonCommandXmlToken(name) || !commandNames.Add(name))
                continue;

            commands.Add(new FirehoseCommandInfo
            {
                Name = name,
                Source = FirehoseCommandSource.InlineDispatch,
                ElfImageOffset = elfImage.ImageOffset
            });
        }
    }

    private void CollectPackedCommandPool(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            int searchOffset = 0;
            while (searchOffset <= data.Length - CallingHandlerText.Length)
            {
                int relativeAnchor = data.Slice(searchOffset).IndexOf(CallingHandlerText);
                if (relativeAnchor < 0)
                    break;

                int anchor = searchOffset + relativeAnchor;
                var reversedNames = new List<string>();
                int terminator = anchor - 1;
                while (terminator >= 0
                       && data[terminator] == 0
                       && reversedNames.Count < MaximumPackedCommandCount)
                {
                    int start = terminator - 1;
                    while (start >= 0 && IsCommandCharacter((char)data[start]))
                        start--;
                    start++;
                    int length = terminator - start;
                    if (length < 2
                        || length > _maximumCommandLength
                        || !TryDecodeCommandName(data.Slice(start, length), out string name))
                    {
                        break;
                    }

                    reversedNames.Add(name);
                    terminator = start - 1;
                }

                reversedNames.Reverse();
                int firstKnown = -1;
                for (int index = 0; index < reversedNames.Count; index++)
                {
                    if (KnownCommandNames.Contains(reversedNames[index]))
                    {
                        firstKnown = index;
                        break;
                    }
                }

                if (firstKnown >= 0
                    && IsCrediblePackedCommandPool(reversedNames, firstKnown))
                {
                    for (int index = firstKnown; index < reversedNames.Count; index++)
                    {
                        string name = reversedNames[index];
                        if (!IsNonCommandXmlToken(name) && inlineNameSet.Add(name))
                            inlineNames.Add(name);
                    }
                }

                searchOffset = anchor + CallingHandlerText.Length;
            }
        }
    }

    private static bool IsCrediblePackedCommandPool(List<string> names, int startIndex)
    {
        var coreNames = new HashSet<string>(StringComparer.Ordinal);
        int knownCommandCount = 0;
        bool hasProgram = false;
        bool hasConfigure = false;
        for (int index = startIndex; index < names.Count; index++)
        {
            string name = names[index];
            if (KnownCommandNames.Contains(name))
                knownCommandCount++;
            if (CoreCommandNames.Contains(name))
                coreNames.Add(name);
            if (name.Equals("program", StringComparison.Ordinal))
                hasProgram = true;
            else if (name.Equals("configure", StringComparison.Ordinal))
                hasConfigure = true;
        }

        int commandCount = names.Count - startIndex;
        return commandCount >= 5
               && hasConfigure
               && (hasProgram && coreNames.Count >= 4
                   || coreNames.Count >= 3 && knownCommandCount == commandCount);
    }

    private static void CollectArm32InlineCommands(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        HashSet<string> tableNames,
        HashSet<string> standalone,
        Dictionary<ulong, string> literals,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        var candidatesByTarget = new Dictionary<ulong, List<Arm32InlineCandidate>>();
        var armGetterTargets = new Dictionary<ulong, bool>();
        var thumbGetterTargets = new Dictionary<ulong, bool>();
        bool requireDispatchEvidence = tableNames.Count == 0;
        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if ((segment.Flags & ExecutableFlag) == 0 || segment.FileSize < sizeof(ushort))
                continue;

            CollectThumbInlineCandidates(
                image,
                elfImage,
                segment,
                standalone,
                literals,
                requireDispatchEvidence,
                thumbGetterTargets,
                candidatesByTarget);
            if (segment.FileSize >= sizeof(uint))
            {
                CollectArmInlineCandidates(
                    image,
                    elfImage,
                    segment,
                    standalone,
                    literals,
                    requireDispatchEvidence,
                    armGetterTargets,
                    candidatesByTarget);
            }
        }

        foreach (KeyValuePair<ulong, List<Arm32InlineCandidate>> pair in candidatesByTarget)
        {
            List<Arm32InlineCandidate> candidates = pair.Value;
            candidates.Sort(static (left, right) => left.InstructionAddress.CompareTo(
                right.InstructionAddress));
            int clusterStart = 0;
            for (int index = 1; index <= candidates.Count; index++)
            {
                bool clusterEnded = index == candidates.Count;
                if (!clusterEnded)
                {
                    ulong previousAddress = candidates[index - 1].InstructionAddress;
                    ulong currentAddress = candidates[index].InstructionAddress;
                    clusterEnded = currentAddress - previousAddress > MaximumArm32CandidateGap;
                }
                if (!clusterEnded)
                    continue;

                CommitArm32CandidateCluster(
                    candidates,
                    clusterStart,
                    index,
                    tableNames,
                    inlineNameSet,
                    inlineNames);
                clusterStart = index;
            }
        }
    }

    private static void CollectThumbInlineCandidates(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        HashSet<string> standalone,
        Dictionary<ulong, string> literals,
        bool requireDispatchEvidence,
        Dictionary<ulong, bool> getterTargets,
        Dictionary<ulong, List<Arm32InlineCandidate>> candidatesByTarget)
    {
        var targetAddresses = new ulong[16];
        var tagOrigins = new int[16];
        ResetArm32TrackedState(targetAddresses, tagOrigins);
        int instructionOrdinal = 0;
        ulong localOffset = (2 - (segment.VirtualAddress & 1)) & 1;
        while (localOffset + sizeof(ushort) <= segment.FileSize)
        {
            ulong fileOffset = segment.FileOffset + localOffset;
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)fileOffset), sizeof(ushort)));
            int scanInstructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
            if (localOffset + checked((ulong)scanInstructionSize) > segment.FileSize)
                break;
            ushort second = scanInstructionSize == sizeof(uint)
                ? BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(
                        checked((int)(fileOffset + sizeof(ushort))),
                        sizeof(ushort)))
                : (ushort)0;

            ulong instructionAddress = segment.VirtualAddress + localOffset;
            instructionOrdinal++;
            if (TryDecodeThumbAddress(
                    image,
                    elfImage,
                    segment,
                    localOffset,
                    instructionAddress,
                    first,
                    out int destinationRegister,
                    out ulong address,
                    out _))
            {
                targetAddresses[destinationRegister] = address;
                tagOrigins[destinationRegister] = -1;
                if (destinationRegister == 1
                    && literals.TryGetValue(address, out string? value)
                    && standalone.Contains(value)
                    && TryFindThumbComparatorCall(
                        image,
                        elfImage,
                        segment,
                        localOffset + checked((ulong)scanInstructionSize),
                        requireDispatchEvidence && !IsInlineAuthenticationTag(value),
                        targetAddresses,
                        out ulong callTarget,
                        out int tagSourceRegister))
                {
                    bool hasGetterEvidence = tagSourceRegister >= 0
                                             && IsCurrentTag(
                                                 tagOrigins[tagSourceRegister],
                                                 instructionOrdinal);
                    AddArm32Candidate(
                        candidatesByTarget,
                        callTarget,
                        value,
                        instructionAddress,
                        hasGetterEvidence);
                }
            }
            else if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                         first,
                         second,
                         out int moveWideDestination,
                         out uint immediate,
                         out bool isHighHalf))
            {
                ulong current = targetAddresses[moveWideDestination];
                targetAddresses[moveWideDestination] = isHighHalf
                    && current != UnknownAddress
                    ? (current & 0xFFFFUL) | ((ulong)immediate << 16)
                    : isHighHalf ? UnknownAddress : immediate;
                tagOrigins[moveWideDestination] = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbMove(
                         first,
                         out int moveDestination,
                         out int moveSource))
            {
                targetAddresses[moveDestination] = targetAddresses[moveSource];
                tagOrigins[moveDestination] = IsCurrentTag(
                    tagOrigins[moveSource],
                    instructionOrdinal)
                    ? tagOrigins[moveSource]
                    : -1;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbDirectCall(
                         first,
                         second,
                         instructionAddress,
                         out ulong directCallTarget))
            {
                bool isTagGetter = IsArm32TagGetter(
                    image,
                    elfImage,
                    directCallTarget,
                    getterTargets);
                ClobberArm32CallRegisters(targetAddresses, tagOrigins);
                if (isTagGetter)
                    tagOrigins[0] = instructionOrdinal;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbRegisterCall(
                         first,
                         out int callRegister))
            {
                ulong indirectCallTarget = targetAddresses[callRegister];
                bool isTagGetter = indirectCallTarget != UnknownAddress
                                   && ArmExecutableImageReader.IsExecutableAddress(
                                       elfImage,
                                       indirectCallTarget)
                                   && IsArm32TagGetter(
                                       image,
                                       elfImage,
                                       indirectCallTarget,
                                       getterTargets);
                ClobberArm32CallRegisters(targetAddresses, tagOrigins);
                if (isTagGetter)
                    tagOrigins[0] = instructionOrdinal;
            }
            else if (ArmInstructionDecoder.IsThumbControlFlowBoundary(
                         first,
                         second,
                         scanInstructionSize))
            {
                ResetArm32TrackedState(targetAddresses, tagOrigins);
            }
            else
            {
                InvalidateThumbWrittenRegisters(
                    first,
                    second,
                    scanInstructionSize,
                    targetAddresses,
                    tagOrigins);
            }

            localOffset += checked((ulong)scanInstructionSize);
        }
    }

    private static bool TryDecodeThumbAddress(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        ulong localOffset,
        ulong instructionAddress,
        ushort first,
        out int destinationRegister,
        out ulong address,
        out int instructionSize)
    {
        ushort second = 0;
        if (ArmInstructionDecoder.GetThumbInstructionSize(first) == sizeof(uint))
        {
            if (localOffset + sizeof(uint) > segment.FileSize)
            {
                destinationRegister = 0;
                address = 0;
                instructionSize = sizeof(ushort);
                return false;
            }

            ulong secondOffset = segment.FileOffset + localOffset + sizeof(ushort);
            second = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)secondOffset), sizeof(ushort)));
        }

        if (!ArmInstructionDecoder.TryDecodeThumbAddress(
                first,
                second,
                instructionAddress,
                out destinationRegister,
                out address,
                out instructionSize,
                out bool isLiteral))
        {
            return false;
        }

        if (!isLiteral)
            return true;

        return ArmExecutableImageReader.TryMapVirtualAddress(
                   elfImage,
                   address,
                   out ulong literalOffset,
                   out ulong available)
               && available >= sizeof(uint)
               && ArmExecutableImageReader.TryReadPointer(
                   image,
                   literalOffset,
                   sizeof(uint),
                   out address);
    }

    private static bool TryFindThumbComparatorCall(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        ulong localOffset,
        bool requireDispatchEvidence,
        ulong[] initialTargetAddresses,
        out ulong callTarget,
        out int tagSourceRegister)
    {
        callTarget = 0;
        tagSourceRegister = -1;
        bool literalRegisterIsLive = true;
        var targetAddresses = new ulong[16];
        Array.Copy(initialTargetAddresses, targetAddresses, targetAddresses.Length);
        for (int index = 0; index < MaximumArm32LookaheadInstructions; index++)
        {
            if (localOffset + sizeof(ushort) > segment.FileSize)
                return false;
            ulong fileOffset = segment.FileOffset + localOffset;
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)fileOffset), sizeof(ushort)));
            int instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
            if (localOffset + checked((ulong)instructionSize) > segment.FileSize)
                return false;
            ushort second = instructionSize == sizeof(uint)
                ? BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(checked((int)(fileOffset + sizeof(ushort))), sizeof(ushort)))
                : (ushort)0;
            ulong instructionAddress = segment.VirtualAddress + localOffset;
            int writtenRegister = -1;

            if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                    first,
                    second,
                    out int moveWideDestination,
                    out uint immediate,
                    out bool isHighHalf))
            {
                writtenRegister = moveWideDestination;
                ulong current = targetAddresses[moveWideDestination];
                targetAddresses[moveWideDestination] = isHighHalf
                    && current != UnknownAddress
                    ? (current & 0xFFFFUL) | ((ulong)immediate << 16)
                    : isHighHalf ? UnknownAddress : immediate;
                if (moveWideDestination == 1)
                    return false;
                if (moveWideDestination == 0 || moveWideDestination == tagSourceRegister)
                    tagSourceRegister = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbMove(
                    first,
                    out int destination,
                    out int source))
            {
                writtenRegister = destination;
                targetAddresses[destination] = targetAddresses[source];
                if (destination == 1)
                    return false;
                if (destination == 0)
                    tagSourceRegister = source is >= 2 and < 15 ? source : -1;
                else if (destination == tagSourceRegister)
                    tagSourceRegister = -1;
            }
            else if (TryDecodeThumbAddress(
                         image,
                         elfImage,
                         segment,
                         localOffset,
                         instructionAddress,
                         first,
                         out destination,
                         out ulong address,
                         out _))
            {
                writtenRegister = destination;
                targetAddresses[destination] = address;
                if (destination == 1)
                    return false;
                if (destination == 0 || destination == tagSourceRegister)
                    tagSourceRegister = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbDirectCall(
                         first,
                         second,
                         instructionAddress,
                         out callTarget))
            {
                return literalRegisterIsLive
                       && tagSourceRegister >= 0
                       && (!requireDispatchEvidence
                           || HasThumbDispatchEvidence(
                               image,
                                segment,
                                localOffset + checked((ulong)instructionSize)));
            }
            else if (ArmInstructionDecoder.TryDecodeThumbRegisterCall(
                         first,
                         out int callRegister))
            {
                ulong registerTarget = targetAddresses[callRegister];
                if (registerTarget == UnknownAddress
                    || !ArmExecutableImageReader.IsExecutableAddress(
                        elfImage,
                        registerTarget))
                {
                    return false;
                }

                callTarget = registerTarget;
                return literalRegisterIsLive
                       && tagSourceRegister >= 0
                       && (!requireDispatchEvidence
                           || HasThumbDispatchEvidence(
                               image,
                               segment,
                               localOffset + checked((ulong)instructionSize)));
            }
            else if (ArmInstructionDecoder.IsThumbControlFlowBoundary(
                         first,
                         second,
                         instructionSize))
            {
                return false;
            }
            else if ((first & 0xF800) == 0x2000 && ((first >> 8) & 7) == 1)
            {
                return false;
            }

            if (writtenRegister < 0
                && tagSourceRegister >= 0
                && (ArmInstructionDecoder.ThumbWritesRegister(
                        first,
                        second,
                        instructionSize,
                        0)
                    || ArmInstructionDecoder.ThumbWritesRegister(
                        first,
                        second,
                        instructionSize,
                        tagSourceRegister)))
            {
                tagSourceRegister = -1;
            }

            if (writtenRegister < 0)
            {
                for (int register = 0; register < targetAddresses.Length; register++)
                {
                    if (ArmInstructionDecoder.ThumbWritesRegister(
                            first,
                            second,
                            instructionSize,
                            register))
                    {
                        targetAddresses[register] = UnknownAddress;
                    }
                }
            }

            if (writtenRegister < 0
                && ArmInstructionDecoder.ThumbWritesRegister(
                    first,
                    second,
                    instructionSize,
                    1))
                literalRegisterIsLive = false;

            localOffset += checked((ulong)instructionSize);
        }

        return false;
    }

    private static bool IsArm32TagGetter(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong callTarget,
        Dictionary<ulong, bool> getterTargets)
    {
        if (!ArmExecutableImageReader.IsExecutableAddress(elfImage, callTarget))
            return false;

        if (!getterTargets.TryGetValue(callTarget, out bool isTagGetter))
        {
            isTagGetter = (callTarget & 1) != 0
                ? LooksLikeThumbTagGetter(image, elfImage, callTarget)
                : LooksLikeArmTagGetter(image, elfImage, callTarget);
            getterTargets.Add(callTarget, isTagGetter);
        }
        return isTagGetter;
    }

    private static bool LooksLikeThumbTagGetter(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong functionAddress)
    {
        functionAddress &= ~1UL;
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                functionAddress,
                out ulong fileOffset,
                out ulong available))
            return false;

        ulong maximumLength = Math.Min(available, MaximumArm32GetterLength);
        bool loadsTypeByte = false;
        bool loadsTagPointer = false;
        int tagValueRegister = -1;
        for (ulong offset = 0; offset + sizeof(ushort) <= maximumLength;)
        {
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)(fileOffset + offset)), sizeof(ushort)));
            int instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
            if (offset + checked((ulong)instructionSize) > maximumLength)
                return false;
            ushort second = instructionSize == sizeof(uint)
                ? BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(
                        checked((int)(fileOffset + offset + sizeof(ushort))),
                        sizeof(ushort)))
                : (ushort)0;

            int baseRegister = (first >> 3) & 7;
            bool loadedPointerThisInstruction = false;
            if ((first & 0xF800) == 0x7800 && baseRegister == 0)
            {
                ulong byteOffset = (ulong)((first >> 6) & 0x1F);
                if (byteOffset <= 4)
                    loadsTypeByte = true;
            }
            if ((first & 0xF800) == 0x6800 && baseRegister == 0)
            {
                ulong byteOffset = (ulong)((first >> 6) & 0x1F) * sizeof(uint);
                if (byteOffset is >= sizeof(uint) and <= 64)
                {
                    loadsTagPointer = true;
                    tagValueRegister = first & 7;
                    loadedPointerThisInstruction = true;
                }
            }
            if (!loadedPointerThisInstruction && tagValueRegister >= 0)
            {
                if (ArmInstructionDecoder.TryDecodeThumbMove(
                        first,
                        out int destination,
                        out int source))
                {
                    tagValueRegister = source == tagValueRegister
                        ? destination
                        : destination == tagValueRegister ? -1 : tagValueRegister;
                }
                else if (ArmInstructionDecoder.ThumbWritesRegister(
                             first,
                             second,
                             instructionSize,
                             tagValueRegister))
                {
                    tagValueRegister = -1;
                }
            }

            if (ArmInstructionDecoder.IsThumbBranchLink(first, second)
                || ArmInstructionDecoder.IsThumbRegisterCall(first))
            {
                return false;
            }
            if (first == 0x4770)
                return loadsTypeByte && loadsTagPointer && tagValueRegister == 0;

            offset += checked((ulong)instructionSize);
        }

        return false;
    }

    private static bool HasThumbDispatchEvidence(
        ReadOnlySpan<byte> image,
        ElfSegment segment,
        ulong localOffset)
    {
        if (!TryReadThumbInstruction(
                image,
                segment,
                localOffset,
                out ushort first,
                out ushort second,
                out int instructionSize)
            || !IsThumbConditionalBranch(first, second, instructionSize))
        {
            return false;
        }

        localOffset += checked((ulong)instructionSize);
        for (int index = 0; index < MaximumArm32DispatchEvidenceInstructions; index++)
        {
            if (!TryReadThumbInstruction(
                    image,
                    segment,
                    localOffset,
                    out first,
                    out second,
                    out instructionSize))
            {
                return false;
            }

            ulong instructionAddress = segment.VirtualAddress + localOffset;
            if (ArmInstructionDecoder.TryDecodeThumbDirectCall(
                    first,
                    second,
                    instructionAddress,
                    out _)
                || ArmInstructionDecoder.TryDecodeThumbRegisterCall(first, out _))
                return true;
            if (ArmInstructionDecoder.IsThumbControlFlowBoundary(
                    first,
                    second,
                    instructionSize))
                return false;
            localOffset += checked((ulong)instructionSize);
        }

        return false;
    }

    private static bool TryReadThumbInstruction(
        ReadOnlySpan<byte> image,
        ElfSegment segment,
        ulong localOffset,
        out ushort first,
        out ushort second,
        out int instructionSize)
    {
        first = 0;
        second = 0;
        instructionSize = 0;
        if (localOffset + sizeof(ushort) > segment.FileSize)
            return false;
        ulong fileOffset = segment.FileOffset + localOffset;
        first = BinaryPrimitives.ReadUInt16LittleEndian(
            image.Slice(checked((int)fileOffset), sizeof(ushort)));
        instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
        if (localOffset + checked((ulong)instructionSize) > segment.FileSize)
            return false;
        if (instructionSize == sizeof(uint))
        {
            second = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)(fileOffset + sizeof(ushort))), sizeof(ushort)));
        }
        return true;
    }

    private static bool IsThumbConditionalBranch(
        ushort first,
        ushort second,
        int instructionSize)
    {
        if ((first & 0xF500) == 0xB100)
            return true;
        if ((first & 0xF000) == 0xD000)
            return ((first >> 8) & 0xF) < 0xE;
        return instructionSize == sizeof(uint)
               && (first & 0xF800) == 0xF000
               && ((first >> 6) & 0xF) < 0xE
               && (second & 0xD000) == 0x8000;
    }

    private static void CollectArmInlineCandidates(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        HashSet<string> standalone,
        Dictionary<ulong, string> literals,
        bool requireDispatchEvidence,
        Dictionary<ulong, bool> getterTargets,
        Dictionary<ulong, List<Arm32InlineCandidate>> candidatesByTarget)
    {
        var targetAddresses = new ulong[16];
        var tagOrigins = new int[16];
        ResetArm32TrackedState(targetAddresses, tagOrigins);
        int instructionOrdinal = 0;
        ulong localOffset = (4 - (segment.VirtualAddress & 3)) & 3;
        while (localOffset + sizeof(uint) <= segment.FileSize)
        {
            ulong fileOffset = segment.FileOffset + localOffset;
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)fileOffset), sizeof(uint)));
            ulong instructionAddress = segment.VirtualAddress + localOffset;
            instructionOrdinal++;
            if (TryDecodeArmAddress(
                    image,
                    elfImage,
                    instruction,
                    instructionAddress,
                    out int destinationRegister,
                    out ulong address))
            {
                targetAddresses[destinationRegister] = address;
                tagOrigins[destinationRegister] = -1;
                if (destinationRegister == 1
                    && literals.TryGetValue(address, out string? value)
                    && standalone.Contains(value)
                    && TryFindArmComparatorCall(
                        image,
                        elfImage,
                        segment,
                        localOffset + sizeof(uint),
                        requireDispatchEvidence && !IsInlineAuthenticationTag(value),
                        targetAddresses,
                        out ulong callTarget,
                        out int tagSourceRegister))
                {
                    bool hasGetterEvidence = tagSourceRegister >= 0
                                             && IsCurrentTag(
                                                 tagOrigins[tagSourceRegister],
                                                 instructionOrdinal);
                    AddArm32Candidate(
                        candidatesByTarget,
                        callTarget,
                        value,
                        instructionAddress,
                        hasGetterEvidence);
                }
            }
            else if (ArmInstructionDecoder.TryDecodeArm32Move(
                         instruction,
                         out int moveDestination,
                         out int moveSource))
            {
                targetAddresses[moveDestination] = targetAddresses[moveSource];
                tagOrigins[moveDestination] = IsCurrentTag(
                    tagOrigins[moveSource],
                    instructionOrdinal)
                    ? tagOrigins[moveSource]
                    : -1;
            }
            else if (ArmInstructionDecoder.TryDecodeArm32MoveWide(
                         instruction,
                         out int moveWideDestination,
                         out uint immediate,
                         out bool isHighHalf))
            {
                ulong current = targetAddresses[moveWideDestination];
                targetAddresses[moveWideDestination] = isHighHalf
                    && current != UnknownAddress
                    ? (current & 0xFFFFUL) | ((ulong)immediate << 16)
                    : isHighHalf ? UnknownAddress : immediate;
                tagOrigins[moveWideDestination] = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeArm32DirectCall(
                         instruction,
                         instructionAddress,
                         out ulong directCallTarget))
            {
                bool isTagGetter = IsArm32TagGetter(
                    image,
                    elfImage,
                    directCallTarget,
                    getterTargets);
                ClobberArm32CallRegisters(targetAddresses, tagOrigins);
                if (isTagGetter)
                    tagOrigins[0] = instructionOrdinal;
            }
            else if (ArmInstructionDecoder.TryDecodeArm32RegisterCall(
                         instruction,
                         out int callRegister))
            {
                ulong indirectCallTarget = targetAddresses[callRegister];
                bool isTagGetter = indirectCallTarget != UnknownAddress
                                   && ArmExecutableImageReader.IsExecutableAddress(
                                       elfImage,
                                       indirectCallTarget)
                                   && IsArm32TagGetter(
                                       image,
                                       elfImage,
                                       indirectCallTarget,
                                       getterTargets);
                ClobberArm32CallRegisters(targetAddresses, tagOrigins);
                if (isTagGetter)
                    tagOrigins[0] = instructionOrdinal;
            }
            else if (ArmInstructionDecoder.IsArm32ControlFlowBoundary(instruction))
            {
                ResetArm32TrackedState(targetAddresses, tagOrigins);
            }
            else
            {
                InvalidateArm32WrittenRegisters(
                    instruction,
                    targetAddresses,
                    tagOrigins);
            }

            localOffset += sizeof(uint);
        }
    }

    private static bool TryDecodeArmAddress(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (ArmInstructionDecoder.TryDecodeArm32ImmediateAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out int sourceRegister,
                out int opcode,
                out uint immediate)
            && sourceRegister == 15)
        {
            ulong pc = instructionAddress + 8;
            if (opcode == 4)
            {
                if (pc > ulong.MaxValue - immediate)
                    return false;
                address = pc + immediate;
                return true;
            }

            if (pc < immediate)
                return false;
            address = pc - immediate;
            return true;
        }

        if (!ArmInstructionDecoder.TryDecodeArm32LiteralAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out ulong literalAddress)
            || !ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                literalAddress,
                out ulong literalOffset,
                out ulong available)
            || available < sizeof(uint))
        {
            return false;
        }

        return ArmExecutableImageReader.TryReadPointer(
            image,
            literalOffset,
            sizeof(uint),
            out address);
    }

    private static bool TryFindArmComparatorCall(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ElfSegment segment,
        ulong localOffset,
        bool requireDispatchEvidence,
        ulong[] initialTargetAddresses,
        out ulong callTarget,
        out int tagSourceRegister)
    {
        callTarget = 0;
        tagSourceRegister = -1;
        bool literalRegisterIsLive = true;
        var targetAddresses = new ulong[16];
        Array.Copy(initialTargetAddresses, targetAddresses, targetAddresses.Length);
        for (int index = 0; index < MaximumArm32LookaheadInstructions; index++)
        {
            if (localOffset + sizeof(uint) > segment.FileSize)
                return false;
            ulong fileOffset = segment.FileOffset + localOffset;
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)fileOffset), sizeof(uint)));
            ulong instructionAddress = segment.VirtualAddress + localOffset;
            int writtenRegister = -1;

            if (ArmInstructionDecoder.TryDecodeArm32Move(
                    instruction,
                    out int destinationRegister,
                    out int sourceRegister))
            {
                writtenRegister = destinationRegister;
                targetAddresses[destinationRegister] = targetAddresses[sourceRegister];
                if (destinationRegister == 1)
                    return false;
                if (destinationRegister == 0)
                {
                    tagSourceRegister = sourceRegister is >= 2 and < 15
                        ? sourceRegister
                        : -1;
                }
                else if (destinationRegister == tagSourceRegister)
                {
                    tagSourceRegister = -1;
                }
            }
            else if (TryDecodeArmAddress(
                         image,
                         elfImage,
                         instruction,
                         instructionAddress,
                         out destinationRegister,
                         out ulong address))
            {
                writtenRegister = destinationRegister;
                targetAddresses[destinationRegister] = address;
                if (destinationRegister == 1)
                    return false;
                if (destinationRegister == 0 || destinationRegister == tagSourceRegister)
                    tagSourceRegister = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeArm32MoveWide(
                         instruction,
                         out destinationRegister,
                         out uint immediate,
                         out bool isHighHalf))
            {
                writtenRegister = destinationRegister;
                ulong current = targetAddresses[destinationRegister];
                targetAddresses[destinationRegister] = isHighHalf
                    && current != UnknownAddress
                    ? (current & 0xFFFFUL) | ((ulong)immediate << 16)
                    : isHighHalf ? UnknownAddress : immediate;
                if (destinationRegister == 1)
                    return false;
                if (destinationRegister == 0 || destinationRegister == tagSourceRegister)
                    tagSourceRegister = -1;
            }
            else if (ArmInstructionDecoder.TryDecodeArm32DirectCall(
                         instruction,
                         instructionAddress,
                         out callTarget))
            {
                return literalRegisterIsLive
                       && tagSourceRegister >= 0
                       && (!requireDispatchEvidence
                           || HasArmDispatchEvidence(
                               image,
                            segment,
                            localOffset + sizeof(uint)));
            }
            else if (ArmInstructionDecoder.TryDecodeArm32RegisterCall(
                         instruction,
                         out int callRegister))
            {
                ulong registerTarget = targetAddresses[callRegister];
                if (registerTarget == UnknownAddress
                    || !ArmExecutableImageReader.IsExecutableAddress(
                        elfImage,
                        registerTarget))
                {
                    return false;
                }

                callTarget = registerTarget;
                return literalRegisterIsLive
                       && tagSourceRegister >= 0
                       && (!requireDispatchEvidence
                           || HasArmDispatchEvidence(
                               image,
                               segment,
                               localOffset + sizeof(uint)));
            }
            else if (ArmInstructionDecoder.IsArm32ControlFlowBoundary(instruction))
            {
                return false;
            }

            if (writtenRegister < 0
                && tagSourceRegister >= 0)
            {
                if (ArmInstructionDecoder.Arm32WritesRegister(instruction, 0)
                    || ArmInstructionDecoder.Arm32WritesRegister(
                        instruction,
                        tagSourceRegister))
                {
                    tagSourceRegister = -1;
                }
            }

            if (writtenRegister < 0)
            {
                for (int register = 0; register < targetAddresses.Length; register++)
                {
                    if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                        targetAddresses[register] = UnknownAddress;
                }

                if (ArmInstructionDecoder.Arm32WritesRegister(instruction, 1))
                    literalRegisterIsLive = false;
            }

            localOffset += sizeof(uint);
        }

        return false;
    }

    private static bool LooksLikeArmTagGetter(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong functionAddress)
    {
        functionAddress &= ~1UL;
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                functionAddress,
                out ulong fileOffset,
                out ulong available))
            return false;

        ulong maximumLength = Math.Min(available, MaximumArm32GetterLength);
        bool loadsTypeByte = false;
        bool loadsTagPointer = false;
        int tagValueRegister = -1;
        for (ulong offset = 0; offset + sizeof(uint) <= maximumLength; offset += sizeof(uint))
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)(fileOffset + offset)), sizeof(uint)));
            bool isImmediateLoad = (instruction & 0x0E000000u) == 0x04000000u
                                   && (instruction & 0x02000000u) == 0
                                   && (instruction & 0x01000000u) != 0
                                   && (instruction & 0x00800000u) != 0
                                   && (instruction & 0x00200000u) == 0
                                   && ((instruction >> 20) & 1u) != 0
                                   && ((instruction >> 16) & 0xFu) == 0;
            bool loadedPointerThisInstruction = false;
            if (isImmediateLoad)
            {
                ulong byteOffset = instruction & 0xFFFu;
                if (((instruction >> 22) & 1u) != 0 && byteOffset <= 4)
                    loadsTypeByte = true;
                if (((instruction >> 22) & 1u) == 0
                    && byteOffset is >= sizeof(uint) and <= 64)
                {
                    loadsTagPointer = true;
                    tagValueRegister = (int)((instruction >> 12) & 0xFu);
                    loadedPointerThisInstruction = true;
                }
            }
            if (!loadedPointerThisInstruction && tagValueRegister >= 0)
            {
                if (ArmInstructionDecoder.TryDecodeArm32Move(
                        instruction,
                        out int destination,
                        out int source))
                {
                    tagValueRegister = source == tagValueRegister
                        ? destination
                        : destination == tagValueRegister ? -1 : tagValueRegister;
                }
                else if (ArmInstructionDecoder.Arm32WritesRegister(
                             instruction,
                             tagValueRegister))
                {
                    tagValueRegister = -1;
                }
            }

            if (ArmInstructionDecoder.IsArm32Call(instruction))
                return false;
            if (ArmInstructionDecoder.IsArm32Return(instruction))
                return loadsTypeByte && loadsTagPointer && tagValueRegister == 0;
        }

        return false;
    }

    private static bool HasArmDispatchEvidence(
        ReadOnlySpan<byte> image,
        ElfSegment segment,
        ulong localOffset)
    {
        if (localOffset + sizeof(uint) > segment.FileSize)
            return false;
        uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
            image.Slice(checked((int)(segment.FileOffset + localOffset)), sizeof(uint)));
        if ((instruction & 0x0F000000) != 0x0A000000
            || (instruction >> 28) >= 0xE)
        {
            return false;
        }

        localOffset += sizeof(uint);
        for (int index = 0; index < MaximumArm32DispatchEvidenceInstructions; index++)
        {
            if (localOffset + sizeof(uint) > segment.FileSize)
                return false;
            instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)(segment.FileOffset + localOffset)), sizeof(uint)));
            ulong instructionAddress = segment.VirtualAddress + localOffset;
            if (ArmInstructionDecoder.TryDecodeArm32DirectCall(
                    instruction,
                    instructionAddress,
                    out _)
                || ArmInstructionDecoder.TryDecodeArm32RegisterCall(instruction, out _))
                return true;
            if (ArmInstructionDecoder.IsArm32ControlFlowBoundary(instruction))
                return false;
            localOffset += sizeof(uint);
        }

        return false;
    }

    private static bool IsNonCommandXmlToken(string name)
    {
        return string.Equals(name, "data", StringComparison.Ordinal)
               || string.Equals(name, "patches", StringComparison.Ordinal)
               || string.Equals(name, "req", StringComparison.Ordinal)
               || string.Equals(name, "storage_type", StringComparison.Ordinal)
               || string.Equals(name, "reset", StringComparison.Ordinal)
               || string.Equals(name, "off", StringComparison.Ordinal)
               || string.Equals(name, "on", StringComparison.Ordinal)
               || string.Equals(name, "in", StringComparison.Ordinal)
               || string.Equals(name, "out", StringComparison.Ordinal)
               || string.Equals(name, "true", StringComparison.Ordinal)
               || string.Equals(name, "false", StringComparison.Ordinal);
    }

    private static bool IsInlineAuthenticationTag(string name)
    {
        return string.Equals(name, "sig", StringComparison.Ordinal);
    }

    private static void AddArm32Candidate(
        Dictionary<ulong, List<Arm32InlineCandidate>> candidatesByTarget,
        ulong callTarget,
        string name,
        ulong instructionAddress,
        bool hasGetterEvidence)
    {
        if (!candidatesByTarget.TryGetValue(
                callTarget,
                out List<Arm32InlineCandidate>? candidates))
        {
            candidates = new List<Arm32InlineCandidate>();
            candidatesByTarget.Add(callTarget, candidates);
        }
        candidates.Add(new Arm32InlineCandidate(
            name,
            instructionAddress,
            hasGetterEvidence));
    }

    private static void CommitArm32CandidateCluster(
        List<Arm32InlineCandidate> candidates,
        int start,
        int end,
        HashSet<string> tableNames,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        var clusterNames = new HashSet<string>(StringComparer.Ordinal);
        var coreNames = new HashSet<string>(StringComparer.Ordinal);
        bool hasTableCommandAnchor = false;
        bool hasGetterBackedAuthenticationTag = false;
        for (int index = start; index < end; index++)
        {
            string name = candidates[index].Name;
            clusterNames.Add(name);
            if (CoreCommandNames.Contains(name))
                coreNames.Add(name);
            if (tableNames.Contains(name))
                hasTableCommandAnchor = true;
            if (IsInlineAuthenticationTag(name) && candidates[index].HasGetterEvidence)
                hasGetterBackedAuthenticationTag = true;
        }
        bool hasDispatchChainAnchor = coreNames.Count >= 2 || hasTableCommandAnchor;
        if (tableNames.Count == 0 && !hasDispatchChainAnchor)
            return;
        if (tableNames.Count > 0
            && !hasDispatchChainAnchor
            && !hasGetterBackedAuthenticationTag)
        {
            return;
        }

        for (int index = start; index < end; index++)
        {
            string name = candidates[index].Name;
            if (tableNames.Contains(name)
                || IsNonCommandXmlToken(name)
                || (tableNames.Count > 0
                    && !hasDispatchChainAnchor
                    && (!IsInlineAuthenticationTag(name)
                        || !candidates[index].HasGetterEvidence))
                || !clusterNames.Remove(name)
                || !inlineNameSet.Add(name))
            {
                continue;
            }
            inlineNames.Add(name);
        }
    }

    private void CollectArm64InlineCommands(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        CommandTable? commandTable,
        HashSet<string> tableNames,
        HashSet<string> standalone,
        Dictionary<ulong, string> literals,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        ulong tableStart = commandTable?.StartAddress ?? 1;
        ulong tableLength = commandTable is null
            ? 0
            : (ulong)commandTable.Entries.Count * (ulong)commandTable.EntrySize;
        ulong tableEnd = tableStart <= ulong.MaxValue - tableLength
            ? tableStart + tableLength
            : ulong.MaxValue;
        var getterTargets = new Dictionary<ulong, bool>();

        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            if ((segment.Flags & ExecutableFlag) == 0 || segment.FileSize < sizeof(uint))
                continue;

            var registerAddresses = new ulong[31];
            var tagOrigins = new int[31];
            ResetArm64Registers(registerAddresses, tagOrigins);

            var functionCandidateGroups = new List<Arm64CandidateGroup>();
            var candidateGroupsByTarget = new Dictionary<ulong, Arm64CandidateGroup>();
            bool hasDispatchTextReference = false;
            bool hasTableReference = false;
            bool hasIndirectCall = false;
            int functionInstructionCount = 0;
            int instructionOrdinal = 0;
            ulong localOffset = (4 - (segment.VirtualAddress & 3)) & 3;

            while (localOffset + sizeof(uint) <= segment.FileSize)
            {
                ulong fileOffset = segment.FileOffset + localOffset;
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)fileOffset), sizeof(uint)));
                ulong instructionAddress = segment.VirtualAddress + localOffset;
                functionInstructionCount++;
                instructionOrdinal++;

                if (TryDecodeArm64Address(
                        instruction,
                        instructionAddress,
                        out int addressRegister,
                        out ulong address,
                        out bool isExactAddress))
                {
                    registerAddresses[addressRegister] = address;
                    tagOrigins[addressRegister] = -1;
                    if (isExactAddress)
                    {
                        UpdateDispatchContext(
                            address,
                            tableStart,
                            tableEnd,
                            literals,
                            ref hasDispatchTextReference,
                            ref hasTableReference);
                    }
                }
                else if (TryDecodeArm64AddImmediate(
                             instruction,
                             registerAddresses,
                             tagOrigins,
                             instructionOrdinal,
                             out int addRegister,
                             out ulong addAddress,
                             out int addTagOrigin))
                {
                    registerAddresses[addRegister] = addAddress;
                    tagOrigins[addRegister] = addTagOrigin;
                    if (addAddress != UnknownAddress)
                    {
                        UpdateDispatchContext(
                            addAddress,
                            tableStart,
                            tableEnd,
                            literals,
                            ref hasDispatchTextReference,
                            ref hasTableReference);
                    }
                }
                else if (ArmInstructionDecoder.TryDecodeArm64Move(
                             instruction,
                             out int moveDestination,
                             out int moveSource))
                {
                    registerAddresses[moveDestination] = registerAddresses[moveSource];
                    tagOrigins[moveDestination] = IsCurrentTag(
                        tagOrigins[moveSource],
                        instructionOrdinal)
                        ? tagOrigins[moveSource]
                        : -1;
                }
                else if (TryDecodeArm64LiteralLoad(
                             image,
                             elfImage,
                             instruction,
                             instructionAddress,
                             out int literalRegister,
                             out ulong literalValue))
                {
                    registerAddresses[literalRegister] = literalValue;
                    tagOrigins[literalRegister] = -1;
                    UpdateDispatchContext(
                        literalValue,
                        tableStart,
                        tableEnd,
                        literals,
                        ref hasDispatchTextReference,
                        ref hasTableReference);
                }
                else if (ArmInstructionDecoder.TryDecodeArm64DirectCall(
                             instruction,
                             instructionAddress,
                             out ulong callTarget))
                {
                    CollectArm64CallCandidates(
                        callTarget,
                        registerAddresses,
                        tagOrigins,
                        instructionOrdinal,
                        tableNames,
                        standalone,
                        literals,
                        candidateGroupsByTarget,
                        functionCandidateGroups);

                    bool isTagGetter;
                    if (!getterTargets.TryGetValue(callTarget, out isTagGetter))
                    {
                        isTagGetter = LooksLikeArm64TagGetter(image, elfImage, callTarget);
                        getterTargets.Add(callTarget, isTagGetter);
                    }

                    ClobberArm64CallRegisters(registerAddresses, tagOrigins);
                    if (isTagGetter)
                        tagOrigins[0] = instructionOrdinal;
                }
                else if (TryDecodeArm64IndirectCall(
                             instruction,
                             instructionAddress,
                             registerAddresses,
                             out ulong indirectCallTarget))
                {
                    CollectArm64CallCandidates(
                        indirectCallTarget,
                        registerAddresses,
                        tagOrigins,
                        instructionOrdinal,
                        tableNames,
                        standalone,
                        literals,
                        candidateGroupsByTarget,
                        functionCandidateGroups);
                    bool isTagGetter = false;
                    if (ArmInstructionDecoder.TryDecodeArm64RegisterCall(
                            instruction,
                            out int targetRegister))
                    {
                        ulong resolvedTarget = registerAddresses[targetRegister];
                        if (resolvedTarget != UnknownAddress
                            && ArmExecutableImageReader.IsExecutableAddress(
                                elfImage,
                                resolvedTarget))
                        {
                            if (!getterTargets.TryGetValue(resolvedTarget, out isTagGetter))
                            {
                                isTagGetter = LooksLikeArm64TagGetter(
                                    image,
                                    elfImage,
                                    resolvedTarget);
                                getterTargets.Add(resolvedTarget, isTagGetter);
                            }
                        }
                    }
                    hasIndirectCall = true;
                    ClobberArm64CallRegisters(registerAddresses, tagOrigins);
                    if (isTagGetter)
                        tagOrigins[0] = instructionOrdinal;
                }
                else
                {
                    InvalidateArm64WrittenRegisters(instruction, registerAddresses, tagOrigins);
                }

                bool functionBoundary = IsArm64FunctionBoundary(
                                            instruction,
                                            instructionAddress,
                                            segment,
                                            functionEntries: null)
                                        || functionInstructionCount >= MaximumFunctionInstructionCount;
                if (functionBoundary)
                {
                    CommitFunctionCandidateGroups(
                        hasTableReference || hasDispatchTextReference && hasIndirectCall,
                        functionCandidateGroups,
                        inlineNameSet,
                        inlineNames);
                    functionCandidateGroups.Clear();
                    candidateGroupsByTarget.Clear();
                    hasDispatchTextReference = false;
                    hasTableReference = false;
                    hasIndirectCall = false;
                    functionInstructionCount = 0;
                    ResetArm64Registers(registerAddresses, tagOrigins);
                }

                localOffset += sizeof(uint);
            }

            CommitFunctionCandidateGroups(
                hasTableReference || hasDispatchTextReference && hasIndirectCall,
                functionCandidateGroups,
                inlineNameSet,
                inlineNames);
        }
    }

    private static void CollectArm64CallCandidates(
        ulong callTarget,
        ulong[] registerAddresses,
        int[] tagOrigins,
        int instructionOrdinal,
        HashSet<string> tableNames,
        HashSet<string> standalone,
        Dictionary<ulong, string> literals,
        Dictionary<ulong, Arm64CandidateGroup> candidateGroupsByTarget,
        List<Arm64CandidateGroup> functionCandidateGroups)
    {
        bool firstIsTag = IsCurrentTag(tagOrigins[0], instructionOrdinal);
        bool secondIsTag = IsCurrentTag(tagOrigins[1], instructionOrdinal);
        int literalRegister;
        if (firstIsTag && !secondIsTag)
            literalRegister = 1;
        else if (secondIsTag && !firstIsTag)
            literalRegister = 0;
        else
            return;

        ulong address = registerAddresses[literalRegister];
        if (address == UnknownAddress
            || !literals.TryGetValue(address, out string? value)
            || !standalone.Contains(value)
            || tableNames.Contains(value))
        {
            return;
        }

        if (!candidateGroupsByTarget.TryGetValue(
                callTarget,
                out Arm64CandidateGroup? candidateGroup))
        {
            candidateGroup = new Arm64CandidateGroup();
            candidateGroupsByTarget.Add(callTarget, candidateGroup);
            functionCandidateGroups.Add(candidateGroup);
        }

        if (candidateGroup.NameSet.Add(value))
            candidateGroup.Names.Add(value);
    }

    private static void CommitFunctionCandidateGroups(
        bool hasDispatchAnchor,
        List<Arm64CandidateGroup> functionCandidateGroups,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        for (int index = 0; index < functionCandidateGroups.Count; index++)
        {
            CommitFunctionCandidates(
                hasDispatchAnchor,
                functionCandidateGroups[index].Names,
                inlineNameSet,
                inlineNames);
        }
    }

    private static void CommitFunctionCandidates(
        bool hasDispatchAnchor,
        List<string> functionCandidates,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        if ((!hasDispatchAnchor && !HasCoreCommandChain(functionCandidates))
            || functionCandidates.Count == 0)
            return;

        for (int index = 0; index < functionCandidates.Count; index++)
        {
            string candidate = functionCandidates[index];
            if (inlineNameSet.Add(candidate))
                inlineNames.Add(candidate);
        }
    }

    private static bool HasCoreCommandChain(List<string> candidates)
    {
        int coreCount = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int index = 0; index < candidates.Count; index++)
        {
            string candidate = candidates[index];
            if (CoreCommandNames.Contains(candidate) && seen.Add(candidate))
                coreCount++;
        }
        return coreCount >= 2;
    }

    private static void UpdateDispatchContext(
        ulong address,
        ulong tableStart,
        ulong tableEnd,
        Dictionary<ulong, string> literals,
        ref bool hasDispatchTextReference,
        ref bool hasTableReference)
    {
        if (address >= tableStart && address < tableEnd)
            hasTableReference = true;

        if (literals.TryGetValue(address, out string? value) && IsDispatchText(value))
        {
            hasDispatchTextReference = true;
        }
    }

    private void CollectDiagnosticInlineCommands(
        List<string> diagnostics,
        HashSet<string> tableNames,
        HashSet<string> standalone,
        HashSet<string> inlineNameSet,
        List<string> inlineNames)
    {
        for (int diagnosticIndex = 0; diagnosticIndex < diagnostics.Count; diagnosticIndex++)
        {
            List<DiagnosticToken> tokens = TokenizeDiagnostic(diagnostics[diagnosticIndex]);
            bool referencesTableCommand = false;
            bool hasTagQualifier = false;
            for (int tokenIndex = 0; tokenIndex < tokens.Count; tokenIndex++)
            {
                string token = tokens[tokenIndex].Value;
                if (tableNames.Contains(token))
                    referencesTableCommand = true;
                if (IsTagQualifier(token))
                    hasTagQualifier = true;
            }

            for (int tokenIndex = 0; tokenIndex < tokens.Count; tokenIndex++)
            {
                string token = tokens[tokenIndex].Value;
                if (token.Equals("tag", StringComparison.Ordinal)
                    || token.Equals("tags", StringComparison.Ordinal)
                    || IsTagQualifier(token)
                    || IsNonCommandXmlToken(token)
                    || tableNames.Contains(token)
                    || !standalone.Contains(token)
                    || !IsNearTagToken(tokens, tokenIndex)
                    || (!referencesTableCommand && !hasTagQualifier)
                    || !inlineNameSet.Add(token))
                {
                    continue;
                }

                inlineNames.Add(token);
            }
        }
    }

    private static bool IsNearTagToken(List<DiagnosticToken> tokens, int candidateIndex)
    {
        int start = Math.Max(0, candidateIndex - 4);
        int end = Math.Min(tokens.Count - 1, candidateIndex + 4);
        for (int index = start; index <= end; index++)
        {
            string token = tokens[index].Value;
            if (token.Equals("tag", StringComparison.Ordinal)
                || token.Equals("tags", StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsTagQualifier(string token)
    {
        return token.Equals("only", StringComparison.Ordinal)
               || token.Equals("allow", StringComparison.Ordinal)
               || token.Equals("allowed", StringComparison.Ordinal)
               || token.Equals("accept", StringComparison.Ordinal)
               || token.Equals("accepted", StringComparison.Ordinal)
               || token.Equals("receive", StringComparison.Ordinal)
               || token.Equals("received", StringComparison.Ordinal)
               || token.Equals("support", StringComparison.Ordinal)
               || token.Equals("supported", StringComparison.Ordinal)
               || token.Equals("unsupported", StringComparison.Ordinal)
               || token.Equals("command", StringComparison.Ordinal);
    }

    private static List<DiagnosticToken> TokenizeDiagnostic(string diagnostic)
    {
        var tokens = new List<DiagnosticToken>();
        int index = 0;
        while (index < diagnostic.Length)
        {
            while (index < diagnostic.Length && !IsDiagnosticTokenCharacter(diagnostic[index]))
                index++;
            int start = index;
            while (index < diagnostic.Length && IsDiagnosticTokenCharacter(diagnostic[index]))
                index++;
            if (index == start)
                continue;

            string token = diagnostic.Substring(start, index - start).ToLowerInvariant();
            tokens.Add(new DiagnosticToken(token));
        }
        return tokens;
    }

    private static bool IsDiagnosticTokenCharacter(char value)
    {
        return value is >= 'A' and <= 'Z'
               or >= 'a' and <= 'z'
               or >= '0' and <= '9'
               or '_'
               or '-';
    }

    private static bool TryDecodeArm64Address(
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address,
        out bool isExactAddress)
    {
        bool decoded = ArmInstructionDecoder.TryDecodeArm64PcRelativeAddress(
            instruction,
            instructionAddress,
            out destinationRegister,
            out address,
            out bool isPageAddress);
        isExactAddress = decoded && !isPageAddress;
        return decoded;
    }

    private static bool IsArm32FunctionBoundary(
        uint instruction,
        ulong instructionAddress,
        ElfSegment segment,
        HashSet<ulong>? functionEntries)
    {
        if (ArmInstructionDecoder.IsArm32Return(instruction)
            || ((instruction & 0x0FFFFFF0u) == 0x012FFF10u
                && !ArmInstructionDecoder.IsArm32Call(instruction))
            || (!ArmInstructionDecoder.IsArm32Call(instruction)
                && ArmInstructionDecoder.Arm32WritesRegister(instruction, 15)))
        {
            return true;
        }

        if ((instruction >> 28) != 0xEu
            || !ArmInstructionDecoder.TryDecodeArm32Branch(
                instruction,
                instructionAddress,
                out ulong target,
                out bool isLink)
            || isLink)
        {
            return false;
        }

        return functionEntries?.Contains(target) == true
               || IsDistantOrExternalBranch(target, instructionAddress, segment);
    }

    private static HashSet<ulong> CollectArm64FunctionEntries(
        ReadOnlySpan<byte> image,
        ElfSegment segment)
    {
        var entries = new HashSet<ulong>();
        int scannedInstructionCount = 0;
        for (ulong offset = 0;
             offset + sizeof(uint) <= segment.FileSize
             && scannedInstructionCount < MaximumFunctionEntryScanInstructionCount
             && entries.Count < MaximumFunctionEntryCount;
             offset += sizeof(uint), scannedInstructionCount++)
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(
                    checked((int)(segment.FileOffset + offset)),
                    sizeof(uint)));
            ulong instructionAddress = segment.VirtualAddress + offset;
            if (ArmInstructionDecoder.TryDecodeArm64DirectCall(
                    instruction,
                    instructionAddress,
                    out ulong target)
                && IsAddressInSegment(target, segment))
            {
                entries.Add(target);
            }
        }
        return entries;
    }

    private static HashSet<ulong> CollectArm32FunctionEntries(
        ReadOnlySpan<byte> image,
        ElfSegment segment)
    {
        var entries = new HashSet<ulong>();
        ulong firstOffset = (4 - (segment.VirtualAddress & 3)) & 3;
        int scannedInstructionCount = 0;
        for (ulong offset = firstOffset;
             offset + sizeof(uint) <= segment.FileSize
             && scannedInstructionCount < MaximumFunctionEntryScanInstructionCount
             && entries.Count < MaximumFunctionEntryCount;
             offset += sizeof(uint), scannedInstructionCount++)
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(
                    checked((int)(segment.FileOffset + offset)),
                    sizeof(uint)));
            ulong instructionAddress = segment.VirtualAddress + offset;
            if (ArmInstructionDecoder.TryDecodeArm32DirectCall(
                    instruction,
                    instructionAddress,
                    out ulong target)
                && (target & 1) == 0
                && IsAddressInSegment(target, segment))
            {
                entries.Add(target);
            }
        }
        return entries;
    }

    private static HashSet<ulong> CollectThumbFunctionEntries(
        ReadOnlySpan<byte> image,
        ElfSegment segment)
    {
        var entries = new HashSet<ulong>();
        ulong offset = (2 - (segment.VirtualAddress & 1)) & 1;
        int scannedInstructionCount = 0;
        while (TryReadThumbInstruction(
                   image,
                   segment,
                   offset,
                   out ushort first,
                   out ushort second,
                   out int instructionSize)
               && scannedInstructionCount < MaximumFunctionEntryScanInstructionCount
               && entries.Count < MaximumFunctionEntryCount)
        {
            scannedInstructionCount++;
            ulong instructionAddress = segment.VirtualAddress + offset;
            if (ArmInstructionDecoder.TryDecodeThumbDirectCall(
                    first,
                    second,
                    instructionAddress,
                    out ulong target)
                && (target & 1) != 0)
            {
                ulong normalizedTarget = target & ~1UL;
                if (IsAddressInSegment(normalizedTarget, segment))
                    entries.Add(normalizedTarget);
            }
            offset += checked((ulong)instructionSize);
        }
        return entries;
    }

    private static bool IsAddressInSegment(ulong address, ElfSegment segment)
    {
        return address >= segment.VirtualAddress
               && address - segment.VirtualAddress < segment.FileSize;
    }

    private static bool IsThumbFunctionBoundary(
        ushort first,
        ushort second,
        int instructionSize,
        ulong instructionAddress,
        ElfSegment segment,
        HashSet<ulong>? functionEntries)
    {
        bool isRegisterBranch = (first & 0xFF87) == 0x4700;
        bool movesToProgramCounter = (first & 0xFF87) == 0x4687;
        if (ArmInstructionDecoder.IsThumbReturn(first)
            || isRegisterBranch
            || movesToProgramCounter)
        {
            return true;
        }

        return ArmInstructionDecoder.TryDecodeThumbUnconditionalBranch(
                   first,
                   second,
                   instructionSize,
                   instructionAddress,
                   out ulong target)
               && (functionEntries?.Contains(target) == true
                   || IsDistantOrExternalBranch(target, instructionAddress, segment));
    }

    private static bool IsArm64FunctionBoundary(
        uint instruction,
        ulong instructionAddress,
        ElfSegment segment,
        HashSet<ulong>? functionEntries)
    {
        if (ArmInstructionDecoder.IsArm64Return(instruction)
            || (instruction & 0xFFFFFC1Fu) == 0xD61F0000u)
        {
            return true;
        }

        if (!ArmInstructionDecoder.TryDecodeArm64UnconditionalBranch(
                instruction,
                instructionAddress,
                out ulong target))
        {
            return false;
        }

        return functionEntries?.Contains(target) == true
               || IsDistantOrExternalBranch(target, instructionAddress, segment);
    }

    private static bool IsDistantOrExternalBranch(
        ulong target,
        ulong instructionAddress,
        ElfSegment segment)
    {
        bool targetIsInSegment = target >= segment.VirtualAddress
                                 && target - segment.VirtualAddress < segment.FileSize;
        ulong distance = target >= instructionAddress
            ? target - instructionAddress
            : instructionAddress - target;
        return !targetIsInSegment || distance > MaximumIntraFunctionBranchDistance;
    }

    private static bool TryDecodeArm64AddImmediate(
        uint instruction,
        ulong[] registerAddresses,
        int[] tagOrigins,
        int instructionOrdinal,
        out int destinationRegister,
        out ulong address,
        out int tagOrigin)
    {
        if (!ArmInstructionDecoder.TryDecodeArm64AddImmediate(
                instruction,
                out destinationRegister,
                out int sourceRegister,
                out ulong immediate,
                out bool is64Bit,
                out bool setsFlags))
        {
            destinationRegister = 0;
            address = UnknownAddress;
            tagOrigin = -1;
            return false;
        }

        ulong sourceAddress = sourceRegister < registerAddresses.Length
            ? registerAddresses[sourceRegister]
            : UnknownAddress;
        address = is64Bit
                  && sourceAddress != UnknownAddress
                  && sourceAddress <= ulong.MaxValue - immediate
            ? sourceAddress + immediate
            : UnknownAddress;
        tagOrigin = is64Bit
                    && !setsFlags
                    && immediate == 0
                    && sourceRegister < tagOrigins.Length
                    && IsCurrentTag(tagOrigins[sourceRegister], instructionOrdinal)
            ? tagOrigins[sourceRegister]
            : -1;
        return destinationRegister < registerAddresses.Length;
    }

    private static bool TryDecodeArm64LiteralLoad(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong value)
    {
        if (!ArmInstructionDecoder.TryDecodeArm64LiteralAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out ulong literalAddress,
                out int pointerSize)
            || pointerSize != sizeof(ulong)
            || !ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                literalAddress,
                out ulong fileOffset,
                out ulong available)
            || available < sizeof(ulong)
            || !ArmExecutableImageReader.TryReadPointer(
                image,
                fileOffset,
                sizeof(ulong),
                out value))
        {
            destinationRegister = 0;
            value = 0;
            return false;
        }

        return true;
    }

    private static bool TryDecodeArm64IndirectCall(
        uint instruction,
        ulong instructionAddress,
        ulong[] registerAddresses,
        out ulong target)
    {
        if (!ArmInstructionDecoder.TryDecodeArm64RegisterCall(
                instruction,
                out int targetRegister))
        {
            target = 0;
            return false;
        }

        target = targetRegister < registerAddresses.Length
                 && registerAddresses[targetRegister] != UnknownAddress
            ? registerAddresses[targetRegister]
            : instructionAddress;
        return true;
    }

    private static bool LooksLikeArm64TagGetter(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong functionAddress)
    {
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                functionAddress,
                out ulong fileOffset,
                out ulong available))
            return false;

        ulong maximumLength = Math.Min(available, 96);
        bool loadsTypeByte = false;
        bool loadsTagPointer = false;
        int tagValueRegister = -1;
        for (ulong offset = 0; offset + sizeof(uint) <= maximumLength; offset += sizeof(uint))
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)(fileOffset + offset)), sizeof(uint)));
            int baseRegister = (int)((instruction >> 5) & 0x1Fu);
            if ((instruction & 0xFFC00000u) == 0x39400000u
                && baseRegister == 0
                && ((instruction >> 10) & 0xFFFu) <= 4)
            {
                loadsTypeByte = true;
            }
            bool loadedPointerThisInstruction = false;
            if ((instruction & 0xFFC00000u) == 0xF9400000u
                && baseRegister == 0)
            {
                ulong byteOffset = ((instruction >> 10) & 0xFFFu) * sizeof(ulong);
                if (byteOffset is >= sizeof(ulong) and <= 64)
                {
                    loadsTagPointer = true;
                    tagValueRegister = (int)(instruction & 0x1Fu);
                    loadedPointerThisInstruction = true;
                }
            }
            if (!loadedPointerThisInstruction && tagValueRegister >= 0)
            {
                if (ArmInstructionDecoder.TryDecodeArm64Move(
                        instruction,
                        out int moveDestination,
                        out int moveSource))
                {
                    tagValueRegister = moveSource == tagValueRegister
                        ? moveDestination
                        : moveDestination == tagValueRegister ? -1 : tagValueRegister;
                }
                else if (ArmInstructionDecoder.Arm64WritesRegister(
                             instruction,
                             tagValueRegister))
                {
                    tagValueRegister = -1;
                }
            }

            if (ArmInstructionDecoder.IsArm64Call(instruction))
                return false;
            if (ArmInstructionDecoder.IsArm64Return(instruction))
                return loadsTypeByte && loadsTagPointer && tagValueRegister == 0;
        }

        return false;
    }

    private static void InvalidateArm64WrittenRegisters(
        uint instruction,
        ulong[] registerAddresses,
        int[] tagOrigins)
    {
        for (int register = 0; register < registerAddresses.Length; register++)
        {
            if (ArmInstructionDecoder.Arm64WritesRegister(instruction, register))
                InvalidateArm64Register(register, registerAddresses, tagOrigins);
        }
    }

    private static void InvalidateArm64Register(
        int register,
        ulong[] registerAddresses,
        int[] tagOrigins)
    {
        if (register >= registerAddresses.Length)
            return;

        registerAddresses[register] = UnknownAddress;
        tagOrigins[register] = -1;
    }

    private static void ClobberArm64CallRegisters(ulong[] registerAddresses, int[] tagOrigins)
    {
        for (int register = 0; register <= 17; register++)
        {
            registerAddresses[register] = UnknownAddress;
            tagOrigins[register] = -1;
        }
    }

    private static void ResetArm64Registers(ulong[] registerAddresses, int[] tagOrigins)
    {
        for (int register = 0; register < registerAddresses.Length; register++)
        {
            registerAddresses[register] = UnknownAddress;
            tagOrigins[register] = -1;
        }
    }

    private static bool IsCurrentTag(int origin, int instructionOrdinal)
    {
        return origin >= 0 && instructionOrdinal - origin <= MaximumTagValueLifetime;
    }

    private void CollectAsciiStrings(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        out HashSet<string> standalone,
        out Dictionary<ulong, string> literals,
        out List<string> diagnostics)
    {
        standalone = new HashSet<string>(StringComparer.Ordinal);
        literals = new Dictionary<ulong, string>();
        diagnostics = new List<string>();
        var diagnosticSet = new HashSet<string>(StringComparer.Ordinal);
        int trackedStringCount = 0;

        for (int segmentIndex = 0; segmentIndex < elfImage.Segments.Count; segmentIndex++)
        {
            ElfSegment segment = elfImage.Segments[segmentIndex];
            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            int index = 0;
            while (index < data.Length)
            {
                while (index < data.Length && !IsPrintableAscii(data[index]))
                    index++;
                int start = index;
                while (index < data.Length && IsPrintableAscii(data[index]))
                    index++;
                int length = index - start;
                bool nullTerminated = index < data.Length && data[index] == 0;
                if (!nullTerminated || length < 2)
                    continue;
                if (trackedStringCount >= MaximumTrackedLiteralCount)
                    continue;
                trackedStringCount++;

                string? commandName = null;
                if (length <= _maximumCommandLength
                    && TryDecodeCommandName(data.Slice(start, length), out string decodedCommandName))
                {
                    commandName = decodedCommandName;
                    standalone.Add(commandName);
                }

                if (length <= MaximumDiagnosticLength)
                {
                    string value = commandName ?? DecodeAscii(data.Slice(start, length));
                    ulong startOffset = checked((ulong)start);
                    if ((commandName is not null || IsDispatchText(value))
                        && literals.Count < MaximumTrackedLiteralCount
                        && segment.VirtualAddress <= ulong.MaxValue - startOffset)
                    {
                        literals[segment.VirtualAddress + startOffset] = value;
                    }
                    if (diagnostics.Count < MaximumDiagnosticCount
                        && ContainsTagWord(value)
                        && diagnosticSet.Add(value))
                    {
                        diagnostics.Add(value);
                    }
                }
            }
        }
    }

    private static bool IsDispatchText(string value)
    {
        return value.IndexOf("Calling handler", StringComparison.OrdinalIgnoreCase) >= 0
               || value.IndexOf("Supported Functions", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool ContainsTagWord(string value)
    {
        if (value.IndexOf("tag", StringComparison.OrdinalIgnoreCase) < 0)
            return false;

        List<DiagnosticToken> tokens = TokenizeDiagnostic(value);
        for (int index = 0; index < tokens.Count; index++)
        {
            string token = tokens[index].Value;
            if (token.Equals("tag", StringComparison.Ordinal)
                || token.Equals("tags", StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private bool TryReadCommandString(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ulong virtualAddress,
        out string commandName)
    {
        commandName = string.Empty;
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                elfImage,
                virtualAddress,
                out ulong fileOffset,
                out ulong available))
            return false;

        int maximumLength = checked((int)Math.Min(available, (ulong)(_maximumCommandLength + 1)));
        if (maximumLength < 3)
            return false;

        ReadOnlySpan<byte> candidate = image.Slice(checked((int)fileOffset), maximumLength);
        int terminator = candidate.IndexOf((byte)0);
        if (terminator < 2 || terminator > _maximumCommandLength)
            return false;

        return TryDecodeCommandName(candidate.Slice(0, terminator), out commandName);
    }

    private static bool TryDecodeCommandName(ReadOnlySpan<byte> value, out string commandName)
    {
        commandName = string.Empty;
        if (value.Length < 2 || value[0] < (byte)'a' || value[0] > (byte)'z')
            return false;

        for (int index = 1; index < value.Length; index++)
        {
            byte current = value[index];
            if (!IsCommandCharacter((char)current))
                return false;
        }

        commandName = DecodeAscii(value);
        return true;
    }

    private static bool IsCommandCharacter(char value)
    {
        return value is >= 'a' and <= 'z'
               or >= '0' and <= '9'
               or '_'
               or '-'
               or '.'
               or ':';
    }

    private static bool HasFirehoseTableSignature(
        List<TableEntry> entries,
        bool hasSupportedFunctionsText,
        bool hasCallingHandlerText)
    {
        bool hasProgram = false;
        bool hasConfigure = false;
        bool hasOperationalCommand = false;
        for (int index = 0; index < entries.Count; index++)
        {
            switch (entries[index].Name)
            {
                case "program":
                    hasProgram = true;
                    break;
                case "configure":
                    hasConfigure = true;
                    break;
                case "read":
                case "nop":
                case "patch":
                case "erase":
                    hasOperationalCommand = true;
                    break;
            }
        }

        if (!hasProgram || !hasOperationalCommand)
            return false;
        return hasSupportedFunctionsText
               || hasCallingHandlerText
               || (entries.Count >= 5 && hasConfigure);
    }

    private static bool ContainsAscii(
        ReadOnlySpan<byte> image,
        ElfImage elfImage,
        ReadOnlySpan<byte> value)
    {
        for (int index = 0; index < elfImage.Segments.Count; index++)
        {
            ElfSegment segment = elfImage.Segments[index];
            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            if (data.IndexOf(value) >= 0)
                return true;
        }
        return false;
    }

    private static byte[] GetAsciiBytes(string value)
    {
        var result = new byte[value.Length];
        for (int index = 0; index < value.Length; index++)
            result[index] = checked((byte)value[index]);
        return result;
    }

    private static string DecodeAscii(ReadOnlySpan<byte> value)
    {
        var characters = new char[value.Length];
        for (int index = 0; index < value.Length; index++)
            characters[index] = (char)value[index];
        return new string(characters);
    }

    private static bool IsPrintableAscii(byte value)
    {
        return value is >= 0x20 and <= 0x7E;
    }

    private static bool Complete(
        FirehoseCommandAnalysisResult result,
        bool success,
        string? error)
    {
        result.IsSuccess = success;
        result.ErrorMessage = error;
        return success;
    }

    private sealed class CommandTable(
        List<TableEntry> entries,
        ulong startAddress,
        int entrySize,
        bool hasDeclaredCount)
    {
        public List<TableEntry> Entries { get; } = entries;
        public ulong StartAddress { get; } = startAddress;
        public int EntrySize { get; } = entrySize;
        public bool HasDeclaredCount { get; } = hasDeclaredCount;
    }

    private sealed class CommandTableHint(
        List<TableEntry> entries,
        ulong startAddress,
        int entrySize,
        CommandTableEvidenceStrength evidenceStrength)
    {
        public List<TableEntry> Entries { get; } = entries;
        public ulong StartAddress { get; } = startAddress;
        public int EntrySize { get; } = entrySize;
        public CommandTableEvidenceStrength EvidenceStrength { get; } = evidenceStrength;

        public bool HasSameTable(CommandTableHint other)
        {
            return StartAddress == other.StartAddress
                   && EntrySize == other.EntrySize
                   && Entries.Count == other.Entries.Count;
        }
    }

    private sealed class CommandTableEvidenceWindow
    {
        private readonly Dictionary<ulong, HashSet<int>> _traversals = new();

        public int AnchorOrdinal { get; private set; } = -1;
        public bool IsActive => AnchorOrdinal >= 0;
        public HashSet<int> MoveCounts { get; } = new();
        public HashSet<int> CompareCounts { get; } = new();
        public HashSet<int> AdvertisedCounts { get; } = new();
        public HashSet<ulong> TableAddresses { get; } = new();

        public void Start(int instructionOrdinal)
        {
            Reset();
            AnchorOrdinal = instructionOrdinal;
        }

        public bool IsExpired(int instructionOrdinal, int maximumDistance)
        {
            return IsActive && instructionOrdinal - AnchorOrdinal > maximumDistance;
        }

        public void AddMoveCount(int value, int minimumCount)
        {
            if (value >= minimumCount && value <= MaximumPackedCommandCount)
                MoveCounts.Add(value);
        }

        public void AddCompareCount(int value, int minimumCount)
        {
            if (value >= minimumCount && value <= MaximumPackedCommandCount)
                CompareCounts.Add(value);
        }

        public void AddAdvertisedCount(int value, int minimumCount)
        {
            if (value < minimumCount || value > MaximumPackedCommandCount)
                return;

            AdvertisedCounts.Add(value);
            MoveCounts.Add(value);
        }

        public void AddTableAddress(ulong address)
        {
            if (address != UnknownAddress)
                TableAddresses.Add(address);
        }

        public void AddTraversal(ulong baseAddress, int stride)
        {
            if (baseAddress == UnknownAddress || stride <= 0)
                return;

            AddTableAddress(baseAddress);
            if (!_traversals.TryGetValue(baseAddress, out HashSet<int>? strides))
            {
                strides = new HashSet<int>();
                _traversals.Add(baseAddress, strides);
            }
            strides.Add(stride);
        }

        public bool HasTraversal(ulong baseAddress, int entrySize)
        {
            return _traversals.TryGetValue(baseAddress, out HashSet<int>? strides)
                   && strides.Contains(entrySize);
        }

        public void Reset()
        {
            AnchorOrdinal = -1;
            MoveCounts.Clear();
            CompareCounts.Clear();
            AdvertisedCounts.Clear();
            TableAddresses.Clear();
            _traversals.Clear();
        }
    }

    private enum CommandTableEvidenceStrength
    {
        NearAnchor = 1,
        AdvertisedCount = 2,
        BoundTraversal = 3,
        AdvertisedCountAndBoundTraversal = 4
    }

    private sealed class Arm64CandidateGroup
    {
        public HashSet<string> NameSet { get; } = new(StringComparer.Ordinal);
        public List<string> Names { get; } = new();
    }

    private readonly struct DiagnosticToken(string value)
    {
        public string Value { get; } = value;
    }

    private readonly struct Arm32InlineCandidate(
        string name,
        ulong instructionAddress,
        bool hasGetterEvidence)
    {
        public string Name { get; } = name;
        public ulong InstructionAddress { get; } = instructionAddress;
        public bool HasGetterEvidence { get; } = hasGetterEvidence;
    }

    private readonly struct TableEntry(
        string name,
        ulong entryAddress,
        ulong handlerAddress)
    {
        public string Name { get; } = name;
        public ulong EntryAddress { get; } = entryAddress;
        public ulong HandlerAddress { get; } = handlerAddress;
    }
}
