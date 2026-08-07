using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using MetadataImage = QcomImageUtils.Utilities.ArmExecutableImage;
using MetadataSegment = QcomImageUtils.Utilities.ArmExecutableSegment;

namespace QcomImageUtils.Utilities;

internal static partial class ImageMetadataExtractor
{
    private static readonly byte[] ElfMagic = { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
    private const int MaximumMetadataElfCount = 4096;
    private const int MaximumMetadataInstructionCount = 16 * 1024 * 1024;

    private static VersionMetadataValues ExtractReferencedVersionValues(
        ReadOnlySpan<byte> image,
        int maximumStringLength,
        int? preferredElfOffset,
        out bool hasAnalyzableCode)
    {
        hasAnalyzableCode = false;
        int remainingInstructionCount = MaximumMetadataInstructionCount;
        var metadataImages = new List<MetadataImage>();

        if (preferredElfOffset is int selectedOffset
            && ArmExecutableImageReader.TryReadElf(
                image,
                selectedOffset,
                out MetadataImage selectedImage)
            && IsAnalyzableArmImage(selectedImage)
            && HasExecutableSegment(selectedImage))
        {
            metadataImages.Add(selectedImage);
        }

        int searchOffset = 0;
        while (searchOffset <= image.Length - ElfMagic.Length)
        {
            int relativeOffset = image.Slice(searchOffset).IndexOf(ElfMagic);
            if (relativeOffset < 0)
                break;

            int elfOffset = searchOffset + relativeOffset;
            if (ArmExecutableImageReader.TryReadElf(image, elfOffset, out MetadataImage elfImage)
                && IsAnalyzableArmImage(elfImage)
                && HasExecutableSegment(elfImage)
                && (preferredElfOffset != elfImage.ImageOffset
                    || metadataImages.Count == 0))
            {
                metadataImages.Add(elfImage);
                if (metadataImages.Count >= MaximumMetadataElfCount)
                    break;
            }

            searchOffset = elfOffset + ElfMagic.Length;
        }

        if (metadataImages.Count == 0
            && ArmExecutableImageReader.TryReadSblMbn(image, out MetadataImage mbnImage)
            && IsAnalyzableArmImage(mbnImage)
            && HasExecutableSegment(mbnImage))
        {
            metadataImages.Add(mbnImage);
        }

        hasAnalyzableCode = metadataImages.Count > 0;
        var bestVersionValues = new VersionMetadataValues();
        var bestBuildTimeValues = new VersionMetadataValues();
        VersionMetadataValues? preferredValues = null;
        for (int index = 0;
             index < metadataImages.Count && remainingInstructionCount > 0;
             index++)
        {
            int remainingImageCount = metadataImages.Count - index;
            int candidateInstructionCount =
                remainingInstructionCount / remainingImageCount;
            int initialCandidateInstructionCount = candidateInstructionCount;
            var candidateValues = new VersionMetadataValues();
            CollectVersionCalls(
                image,
                metadataImages[index],
                maximumStringLength,
                candidateValues,
                ref candidateInstructionCount);
            remainingInstructionCount -=
                initialCandidateInstructionCount - candidateInstructionCount;

            if (preferredElfOffset == metadataImages[index].ImageOffset)
                preferredValues = candidateValues;
            if (candidateValues.HasBetterVersionSetThan(bestVersionValues))
                bestVersionValues = candidateValues;
            if (candidateValues.HasBetterBuildTimeThan(bestBuildTimeValues))
                bestBuildTimeValues = candidateValues;
        }

        var selectedValues = new VersionMetadataValues();
        VersionMetadataValues versionSource = preferredValues is
        { HasVersionFields: true } selectedVersionSource
            ? selectedVersionSource
            : bestVersionValues;
        selectedValues.ApplyVersionFields(versionSource);
        selectedValues.ApplyBuildTime(bestBuildTimeValues);
        return selectedValues;
    }

    private static void CollectVersionCalls(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        int maximumStringLength,
        VersionMetadataValues values,
        ref int remainingInstructionCount)
    {
        if (metadataImage.Machine == Arm64Machine)
        {
            CollectArm64VersionCalls(
                image,
                metadataImage,
                maximumStringLength,
                values,
                ref remainingInstructionCount);
        }
        else if (metadataImage.Machine == ArmMachine)
        {
            // EM_ARM images can mix ARM and Thumb code. Keep a fair share of the
            // global scan budget for each decoder instead of letting ARM consume it all.
            int arm32InstructionCount = remainingInstructionCount / 2;
            int initialArm32InstructionCount = arm32InstructionCount;
            CollectArm32VersionCalls(
                image,
                metadataImage,
                maximumStringLength,
                values,
                ref arm32InstructionCount);
            remainingInstructionCount -=
                initialArm32InstructionCount - arm32InstructionCount;
            if (!values.HasAll && remainingInstructionCount > 0)
            {
                CollectThumbVersionCalls(
                    image,
                    metadataImage,
                    maximumStringLength,
                    values,
                    ref remainingInstructionCount);
            }
        }
    }

    private static void CollectArm64VersionCalls(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        int maximumStringLength,
        VersionMetadataValues values,
        ref int remainingInstructionCount)
    {
        var registers = new ulong?[32];
        for (int segmentIndex = 0; segmentIndex < metadataImage.Segments.Count; segmentIndex++)
        {
            MetadataSegment segment = metadataImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            int fileOffset = checked((int)segment.FileOffset);
            int fileSize = checked((int)segment.FileSize);
            int firstInstructionOffset = checked((int)((4 - (segment.VirtualAddress & 3)) & 3));
            for (int localOffset = firstInstructionOffset;
                 localOffset + 4 <= fileSize;
                 localOffset += 4)
            {
                if (remainingInstructionCount <= 0)
                    return;
                remainingInstructionCount--;

                ulong instructionAddress = segment.VirtualAddress + checked((ulong)localOffset);
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(fileOffset + localOffset, 4));

                if (ArmInstructionDecoder.IsArm64Call(instruction))
                {
                    TryApplyMetadataCall(
                        image,
                        metadataImage,
                        registers,
                        8,
                        maximumStringLength,
                        values);
                    if (values.HasAll)
                        return;

                    InvalidateArm64CallerSaved(registers);
                    continue;
                }

                if (ArmInstructionDecoder.IsArm64ControlFlowBoundary(instruction))
                {
                    Array.Clear(registers, 0, registers.Length);
                    continue;
                }

                if (ArmInstructionDecoder.TryDecodeArm64PcRelativeAddress(
                        instruction,
                        instructionAddress,
                        out int destinationRegister,
                        out ulong addressValue,
                        out _)
                    || TryDecodeArm64AddImmediate(
                        instruction,
                        registers,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm64MoveRegister(
                        instruction,
                        registers,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm64MoveWide(
                        instruction,
                        registers,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm64LiteralLoad(
                        image,
                        metadataImage,
                        instruction,
                        instructionAddress,
                        out destinationRegister,
                        out addressValue))
                {
                    registers[destinationRegister] = addressValue;
                    continue;
                }

                InvalidateArm64MetadataRegisters(instruction, registers);
            }
        }
    }

    private static void CollectArm32VersionCalls(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        int maximumStringLength,
        VersionMetadataValues values,
        ref int remainingInstructionCount)
    {
        var registers = new ulong?[16];
        for (int segmentIndex = 0; segmentIndex < metadataImage.Segments.Count; segmentIndex++)
        {
            MetadataSegment segment = metadataImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            int fileOffset = checked((int)segment.FileOffset);
            int fileSize = checked((int)segment.FileSize);
            int firstInstructionOffset = checked((int)((4 - (segment.VirtualAddress & 3)) & 3));
            for (int localOffset = firstInstructionOffset;
                 localOffset + 4 <= fileSize;
                 localOffset += 4)
            {
                if (remainingInstructionCount <= 0)
                    return;
                remainingInstructionCount--;

                ulong instructionAddress = segment.VirtualAddress + checked((ulong)localOffset);
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(fileOffset + localOffset, 4));

                if (ArmInstructionDecoder.IsArm32Call(instruction))
                {
                    TryApplyMetadataCall(
                        image,
                        metadataImage,
                        registers,
                        4,
                        maximumStringLength,
                        values);
                    if (values.HasAll)
                        return;

                    InvalidateArm32CallerSaved(registers);
                    continue;
                }

                if (ArmInstructionDecoder.IsArm32ControlFlowBoundary(instruction))
                {
                    Array.Clear(registers, 0, registers.Length);
                    continue;
                }

                if (TryDecodeArm32LiteralLoad(
                        image,
                        metadataImage,
                        instruction,
                        instructionAddress,
                        out int destinationRegister,
                        out ulong addressValue)
                    || TryDecodeArm32MoveImmediate(
                        instruction,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm32MoveRegister(
                        instruction,
                        registers,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm32MoveWide(
                        instruction,
                        registers,
                        out destinationRegister,
                        out addressValue)
                    || TryDecodeArm32ImmediateAddress(
                        instruction,
                        instructionAddress,
                        registers,
                        out destinationRegister,
                        out addressValue))
                {
                    registers[destinationRegister] = addressValue;
                    continue;
                }

                InvalidateArm32MetadataRegisters(instruction, registers);
            }
        }
    }

    private static void CollectThumbVersionCalls(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        int maximumStringLength,
        VersionMetadataValues values,
        ref int remainingInstructionCount)
    {
        var registers = new ulong?[16];
        for (int segmentIndex = 0; segmentIndex < metadataImage.Segments.Count; segmentIndex++)
        {
            MetadataSegment segment = metadataImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            int fileOffset = checked((int)segment.FileOffset);
            int fileSize = checked((int)segment.FileSize);
            int localOffset = checked((int)((2 - (segment.VirtualAddress & 1)) & 1));
            while (localOffset + 2 <= fileSize)
            {
                if (remainingInstructionCount <= 0)
                    return;
                remainingInstructionCount--;

                ulong instructionAddress = segment.VirtualAddress + checked((ulong)localOffset);
                ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(fileOffset + localOffset, 2));
                int instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
                if (localOffset + instructionSize > fileSize)
                    break;
                ushort second = instructionSize == sizeof(uint)
                    ? BinaryPrimitives.ReadUInt16LittleEndian(
                        image.Slice(fileOffset + localOffset + 2, 2))
                    : (ushort)0;

                if (instructionSize == sizeof(uint)
                    && ArmInstructionDecoder.IsThumbBranchLink(first, second))
                {
                    TryApplyMetadataCall(
                        image,
                        metadataImage,
                        registers,
                        4,
                        maximumStringLength,
                        values);
                    if (values.HasAll)
                        return;

                    InvalidateArm32CallerSaved(registers);
                    localOffset += instructionSize;
                    continue;
                }

                if (ArmInstructionDecoder.IsThumbRegisterCall(first))
                {
                    TryApplyMetadataCall(
                        image,
                        metadataImage,
                        registers,
                        4,
                        maximumStringLength,
                        values);
                    if (values.HasAll)
                        return;

                    InvalidateArm32CallerSaved(registers);
                    localOffset += instructionSize;
                    continue;
                }

                if (ArmInstructionDecoder.IsThumbControlFlowBoundary(
                        first,
                        second,
                        instructionSize))
                {
                    Array.Clear(registers, 0, registers.Length);
                    localOffset += instructionSize;
                    continue;
                }

                if (TryResolveThumbAddress(
                        image,
                        metadataImage,
                        first,
                        second,
                        instructionAddress,
                        out int destinationRegister,
                        out ulong addressValue,
                        out int decodedSize))
                {
                    registers[destinationRegister] = addressValue;
                    localOffset += decodedSize;
                    continue;
                }

                if (ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
                        first,
                        second,
                        out destinationRegister,
                        out uint moveImmediate))
                {
                    registers[destinationRegister] = moveImmediate;
                }
                else if (ArmInstructionDecoder.TryDecodeThumbAddSubtractImmediate(
                             first,
                             second,
                             out destinationRegister,
                             out int arithmeticSourceRegister,
                             out uint arithmeticImmediate,
                             out bool subtracts))
                {
                    if (destinationRegister < 15)
                    {
                        ulong? source = registers[arithmeticSourceRegister];
                        if (!source.HasValue
                            || subtracts && source.Value < arithmeticImmediate
                            || !subtracts && source.Value > ulong.MaxValue - arithmeticImmediate)
                        {
                            registers[destinationRegister] = null;
                        }
                        else
                        {
                            registers[destinationRegister] = subtracts
                                ? source.Value - arithmeticImmediate
                                : source.Value + arithmeticImmediate;
                        }
                    }
                }
                else if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                        first,
                        second,
                        out destinationRegister,
                        out uint immediate,
                        out bool isHighHalf))
                {
                    ulong? current = registers[destinationRegister];
                    registers[destinationRegister] = isHighHalf
                        && current.HasValue
                        ? (current.Value & 0xFFFFUL) | ((ulong)immediate << 16)
                        : isHighHalf ? null : immediate;
                }
                else if (ArmInstructionDecoder.TryDecodeThumbMove(
                        first,
                        out destinationRegister,
                        out int sourceRegister))
                {
                    registers[destinationRegister] = registers[sourceRegister];
                }
                else
                {
                    for (int register = 0; register < registers.Length; register++)
                    {
                        if (ArmInstructionDecoder.ThumbWritesRegister(
                                first,
                                second,
                                instructionSize,
                                register))
                        {
                            registers[register] = null;
                        }
                    }
                }

                localOffset += instructionSize;
            }
        }
    }

    private static void TryApplyMetadataCall(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        ulong?[] registers,
        int argumentRegisterCount,
        int maximumStringLength,
        VersionMetadataValues values)
    {
        TryApplyVersionArguments(
            image,
            metadataImage,
            registers,
            argumentRegisterCount,
            maximumStringLength,
            values);

        if (!string.IsNullOrEmpty(values.BuildTime))
            return;

        int lastFormatRegister = argumentRegisterCount - 3;
        for (int formatRegister = 0;
             formatRegister <= lastFormatRegister;
             formatRegister++)
        {
            ulong? formatAddress = registers[formatRegister];
            ulong? dateAddress = registers[formatRegister + 1];
            ulong? timeAddress = registers[formatRegister + 2];
            if (!formatAddress.HasValue
                || !dateAddress.HasValue
                || !timeAddress.HasValue
                || !TryReadStringAtAddress(
                    image,
                    metadataImage,
                    formatAddress.Value,
                    BuildDateFormat.Length + 2,
                    out string format)
                || !IsBuildDateFormat(format)
                || !TryReadStringAtAddress(
                    image,
                    metadataImage,
                    dateAddress.Value,
                    maximumStringLength,
                    out string date)
                || !TryReadStringAtAddress(
                    image,
                    metadataImage,
                    timeAddress.Value,
                    maximumStringLength,
                    out string time))
            {
                continue;
            }

            values.TryApplyBuildTime(date, time);
            if (!string.IsNullOrEmpty(values.BuildTime))
                return;
        }
    }

    private static void TryApplyVersionArguments(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        ulong?[] registers,
        int argumentRegisterCount,
        int maximumStringLength,
        VersionMetadataValues values)
    {
        int maximumKeyLength = Math.Max(
            QcVersionKey.Length,
            Math.Max(OemVersionKey.Length, ImageVariantKey.Length));
        int maximumFullLength = checked(maximumStringLength + maximumKeyLength);
        for (int register = 0;
             register < argumentRegisterCount && register < registers.Length;
             register++)
        {
            ulong? address = registers[register];
            if (!address.HasValue
                || !TryReadStringAtAddress(
                    image,
                    metadataImage,
                    address.Value,
                    maximumFullLength,
                    out string metadataText))
            {
                continue;
            }

            values.TryApply(metadataText);
        }
    }

    private static bool IsBuildDateFormat(string format)
    {
        if (!format.StartsWith(BuildDateFormat, StringComparison.Ordinal))
            return false;

        for (int index = BuildDateFormat.Length; index < format.Length; index++)
        {
            if (format[index] is not ('\r' or '\n'))
                return false;
        }

        return true;
    }

    private static bool TryDecodeArm64AddImmediate(
        uint instruction,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm64AddImmediate(
                instruction,
                out destinationRegister,
                out int sourceRegister,
                out ulong immediate,
                out bool is64Bit,
                out bool setsFlags)
            || !is64Bit
            || setsFlags
            || !registers[sourceRegister].HasValue
            || registers[sourceRegister]!.Value > ulong.MaxValue - immediate)
        {
            destinationRegister = 0;
            return false;
        }

        address = registers[sourceRegister]!.Value + immediate;
        return true;
    }

    private static bool TryDecodeArm64MoveRegister(
        uint instruction,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm64Move(
                instruction,
                out destinationRegister,
                out int sourceRegister)
            || !registers[sourceRegister].HasValue)
        {
            destinationRegister = 0;
            return false;
        }

        address = registers[sourceRegister]!.Value;
        return true;
    }

    private static bool TryDecodeArm64MoveWide(
        uint instruction,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm64MoveWide(
                instruction,
                out destinationRegister,
                out ulong value,
                out ulong writeMask,
                out bool keepsOtherBits))
        {
            destinationRegister = 0;
            return false;
        }

        if (!keepsOtherBits)
        {
            address = value;
            return true;
        }

        ulong? current = registers[destinationRegister];
        if (!current.HasValue)
            return false;

        address = (current.Value & ~writeMask) | (value & writeMask);
        return true;
    }

    private static bool TryDecodeArm64LiteralLoad(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm64LiteralAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out ulong literalAddress,
                out int pointerSize)
            || !TryReadPointerAtAddress(
                image,
                metadataImage,
                literalAddress,
                pointerSize,
                out address))
        {
            destinationRegister = 0;
            return false;
        }

        return true;
    }

    private static bool TryDecodeArm32LiteralLoad(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm32LiteralAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out ulong literalAddress)
            || !TryReadPointerAtAddress(
                image,
                metadataImage,
                literalAddress,
                sizeof(uint),
                out address))
        {
            destinationRegister = 0;
            return false;
        }
        return true;
    }

    private static bool TryDecodeArm32MoveImmediate(
        uint instruction,
        out int destinationRegister,
        out ulong address)
    {
        if (!ArmInstructionDecoder.TryDecodeArm32MoveImmediate(
                instruction,
                out destinationRegister,
                out uint value))
        {
            address = 0;
            return false;
        }

        address = value;
        return true;
    }

    private static bool TryDecodeArm32MoveRegister(
        uint instruction,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm32Move(
                instruction,
                out destinationRegister,
                out int sourceRegister)
            || !registers[sourceRegister].HasValue)
        {
            destinationRegister = 0;
            return false;
        }
        address = registers[sourceRegister]!.Value;
        return true;
    }

    private static bool TryDecodeArm32MoveWide(
        uint instruction,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm32MoveWide(
                instruction,
                out destinationRegister,
                out uint immediate,
                out bool isHighHalf))
        {
            destinationRegister = 0;
            return false;
        }

        if (!isHighHalf)
        {
            address = immediate;
            return true;
        }

        ulong? existingAddress = registers[destinationRegister];
        if (!existingAddress.HasValue)
            return false;

        address = (existingAddress.Value & 0xFFFFUL) | ((ulong)immediate << 16);
        return true;
    }

    private static bool TryDecodeArm32ImmediateAddress(
        uint instruction,
        ulong instructionAddress,
        ulong?[] registers,
        out int destinationRegister,
        out ulong address)
    {
        address = 0;
        if (!ArmInstructionDecoder.TryDecodeArm32ImmediateAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out int sourceRegister,
                out int opcode,
                out uint immediate))
        {
            destinationRegister = 0;
            return false;
        }

        ulong? sourceValue = sourceRegister == 15
            ? instructionAddress + 8
            : registers[sourceRegister];
        if (!sourceValue.HasValue)
            return false;

        if (opcode == 4)
        {
            if (sourceValue.Value > ulong.MaxValue - immediate)
                return false;

            address = sourceValue.Value + immediate;
            return true;
        }

        if (sourceValue.Value < immediate)
            return false;

        address = sourceValue.Value - immediate;
        return true;
    }

    private static bool TryResolveThumbAddress(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        ushort first,
        ushort second,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address,
        out int instructionSize)
    {
        if (!ArmInstructionDecoder.TryDecodeThumbAddress(
                first,
                second,
                instructionAddress,
                out destinationRegister,
                out address,
                out instructionSize,
                out bool isLiteral))
        {
            destinationRegister = 0;
            address = 0;
            instructionSize = sizeof(ushort);
            return false;
        }

        return !isLiteral
               || TryReadPointerAtAddress(
                   image,
                   metadataImage,
                   address,
                   sizeof(uint),
                   out address);
    }

    private static bool TryReadStringAtAddress(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        ulong address,
        int maximumStringLength,
        out string value)
    {
        value = string.Empty;
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                metadataImage,
                address,
                out ulong fileOffset,
                out ulong available)
            || fileOffset > int.MaxValue)
        {
            return false;
        }

        int readableLength = checked((int)Math.Min(
            available,
            (ulong)maximumStringLength + 1));
        return TryExtractNullTerminated(
            image.Slice(checked((int)fileOffset), readableLength),
            0,
            maximumStringLength,
            out value,
            out _);
    }

    private static bool TryReadPointerAtAddress(
        ReadOnlySpan<byte> image,
        MetadataImage metadataImage,
        ulong address,
        int pointerSize,
        out ulong value)
    {
        value = 0;
        if (!ArmExecutableImageReader.TryMapVirtualRange(
                metadataImage,
                address,
                (uint)pointerSize,
                out ulong fileOffset)
            || fileOffset > int.MaxValue)
        {
            return false;
        }

        return ArmExecutableImageReader.TryReadPointer(
            image,
            fileOffset,
            pointerSize,
            out value);
    }

    private static bool IsAnalyzableArmImage(MetadataImage metadataImage)
    {
        return metadataImage.Machine is ArmMachine or Arm64Machine;
    }

    private static bool HasExecutableSegment(MetadataImage metadataImage)
    {
        for (int index = 0; index < metadataImage.Segments.Count; index++)
        {
            if (metadataImage.Segments[index].IsExecutable)
                return true;
        }

        return false;
    }

    private static void InvalidateArm64MetadataRegisters(
        uint instruction,
        ulong?[] registers)
    {
        for (int register = 0; register < registers.Length && register < 31; register++)
        {
            if (ArmInstructionDecoder.Arm64WritesRegister(instruction, register))
                registers[register] = null;
        }
    }

    private static void InvalidateArm32MetadataRegisters(
        uint instruction,
        ulong?[] registers)
    {
        for (int register = 0; register < registers.Length && register < 15; register++)
        {
            if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                registers[register] = null;
        }
    }

    private static void InvalidateArm64CallerSaved(ulong?[] registers)
    {
        for (int index = 0; index <= 18; index++)
            registers[index] = null;
        registers[30] = null;
    }

    private static void InvalidateArm32CallerSaved(ulong?[] registers)
    {
        registers[0] = null;
        registers[1] = null;
        registers[2] = null;
        registers[3] = null;
        registers[12] = null;
        registers[14] = null;
    }

    private sealed class VersionMetadataValues
    {
        public string QcVersion { get; private set; } = string.Empty;
        public string OemVersion { get; private set; } = string.Empty;
        public string ImageVariant { get; private set; } = string.Empty;
        public string BuildTime { get; private set; } = string.Empty;
        public string? BuildTimeDebug { get; private set; }

        public bool HasAll => !string.IsNullOrEmpty(QcVersion)
                              && !string.IsNullOrEmpty(OemVersion)
                              && !string.IsNullOrEmpty(ImageVariant)
                              && !string.IsNullOrEmpty(BuildTime);

        public bool HasVersionFields => CountVersionFields() > 0;

        public bool HasBetterVersionSetThan(VersionMetadataValues other)
        {
            return CountVersionFields() > other.CountVersionFields();
        }

        public bool HasBetterBuildTimeThan(VersionMetadataValues other)
        {
            bool hasBuildTime = !string.IsNullOrEmpty(BuildTime);
            bool otherHasBuildTime = !string.IsNullOrEmpty(other.BuildTime);
            return hasBuildTime != otherHasBuildTime
                ? hasBuildTime
                : BuildTimeDebug is not null && other.BuildTimeDebug is null;
        }

        public void ApplyVersionFields(VersionMetadataValues source)
        {
            QcVersion = source.QcVersion;
            OemVersion = source.OemVersion;
            ImageVariant = source.ImageVariant;
        }

        public void ApplyBuildTime(VersionMetadataValues source)
        {
            BuildTime = source.BuildTime;
            BuildTimeDebug = source.BuildTimeDebug;
        }

        public void TryApplyBuildTime(string date, string time)
        {
            if (!string.IsNullOrEmpty(BuildTime))
                return;

            string value = CombineBuildTimeParts(date, time);
            if (TryNormalizeBuildTime(value, out string buildTime))
            {
                BuildTime = buildTime;
                BuildTimeDebug = null;
                return;
            }

            BuildTimeDebug ??= $"无法解析构建时间: {value}";
        }

        public void TryApply(string text)
        {
            if (string.IsNullOrEmpty(QcVersion)
                && text.StartsWith(QcVersionKey, StringComparison.Ordinal))
            {
                string value = text.Substring(QcVersionKey.Length);
                if (value.Length > 0)
                    QcVersion = value;
                return;
            }

            if (string.IsNullOrEmpty(OemVersion)
                && text.StartsWith(OemVersionKey, StringComparison.Ordinal))
            {
                string value = text.Substring(OemVersionKey.Length);
                if (value.Length > 0)
                    OemVersion = value;
                return;
            }

            if (string.IsNullOrEmpty(ImageVariant)
                && text.StartsWith(ImageVariantKey, StringComparison.Ordinal))
            {
                string value = text.Substring(ImageVariantKey.Length);
                if (value.Length > 0)
                    ImageVariant = value;
            }
        }

        private int CountVersionFields()
        {
            int count = 0;
            if (!string.IsNullOrEmpty(QcVersion))
                count++;
            if (!string.IsNullOrEmpty(OemVersion))
                count++;
            if (!string.IsNullOrEmpty(ImageVariant))
                count++;
            return count;
        }
    }
}
