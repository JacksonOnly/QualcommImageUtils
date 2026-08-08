using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace QcomImageUtils.Utilities;

internal static class FirehosePayloadSizeAnalyzer
{
    private static readonly byte[] SupportedAttribute =
        Encoding.ASCII.GetBytes("MaxPayloadSizeToTargetInBytesSupported");
    private static readonly byte[] PayloadNak = Encoding.ASCII.GetBytes(
        "NAK: MaxPayloadSizeToTargetInBytes sent by host %d larger than supported %d\0");

    private const ulong MinimumPlausiblePayloadSize = 4 * 1024;
    private const ulong MaximumPlausiblePayloadSize = 64 * 1024 * 1024;
    private const int MaximumConstantReturnInstructions = 12;

    public static bool TryAnalyze(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        out ulong supportedSize)
    {
        var supportedAddresses = new HashSet<ulong>();
        var nakAddresses = new HashSet<ulong>();
        CollectStringAddresses(image, executableImage, SupportedAttribute, supportedAddresses);
        CollectStringAddresses(image, executableImage, PayloadNak, nakAddresses);
        if (supportedAddresses.Count == 0 && nakAddresses.Count == 0)
        {
            supportedSize = 0;
            return false;
        }

        var candidates = new Dictionary<ulong, int>();
        if (executableImage.Machine == ArmExecutableImageReader.Arm64Machine)
        {
            CollectArm64Candidates(
                image,
                executableImage,
                supportedAddresses,
                nakAddresses,
                candidates);
        }
        else if (executableImage.Machine == ArmExecutableImageReader.ArmMachine)
        {
            var constantReturns = new Dictionary<ulong, ulong?>();
            CollectThumbAddressProximityCandidates(
                image,
                executableImage,
                supportedAddresses,
                candidates);
            CollectArm32Candidates(
                image,
                executableImage,
                supportedAddresses,
                nakAddresses,
                candidates,
                constantReturns);
            CollectThumbCandidates(
                image,
                executableImage,
                supportedAddresses,
                nakAddresses,
                candidates,
                constantReturns);
        }

        supportedSize = 0;
        int bestEvidenceCount = 0;
        foreach (KeyValuePair<ulong, int> candidate in candidates)
        {
            if (candidate.Value > bestEvidenceCount
                || candidate.Value == bestEvidenceCount && candidate.Key > supportedSize)
            {
                supportedSize = candidate.Key;
                bestEvidenceCount = candidate.Value;
            }
        }

        return bestEvidenceCount > 0;
    }

    private static void CollectStringAddresses(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ReadOnlySpan<byte> needle,
        HashSet<ulong> addresses)
    {
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (segment.FileSize < (ulong)needle.Length)
                continue;

            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            int searchOffset = 0;
            while (searchOffset <= data.Length - needle.Length)
            {
                int relativeOffset = data.Slice(searchOffset).IndexOf(needle);
                if (relativeOffset < 0)
                    break;

                int localOffset = searchOffset + relativeOffset;
                addresses.Add(segment.VirtualAddress + checked((ulong)localOffset));
                searchOffset = localOffset + needle.Length;
            }
        }
    }

    private static void CollectArm64Candidates(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        HashSet<ulong> supportedAddresses,
        HashSet<ulong> nakAddresses,
        Dictionary<ulong, int> candidates)
    {
        var registers = new ulong?[31];
        var constantReturns = new Dictionary<ulong, ulong?>();
        Dictionary<ulong, ulong?> storedFieldValues = CollectArm64StoredFieldValues(
            image,
            executableImage);
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            ulong firstOffset = (4 - (segment.VirtualAddress & 3)) & 3;
            for (ulong localOffset = firstOffset;
                 localOffset + sizeof(uint) <= segment.FileSize;
                 localOffset += sizeof(uint))
            {
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)(segment.FileOffset + localOffset)), sizeof(uint)));
                ulong instructionAddress = segment.VirtualAddress + localOffset;

                if (ArmInstructionDecoder.IsArm64Call(instruction))
                {
                    CollectCallCandidate(
                        registers,
                        supportedAddresses,
                        nakAddresses,
                        candidates);

                    ulong? returnValue = null;
                    if (ArmInstructionDecoder.TryDecodeArm64DirectCall(
                            instruction,
                            instructionAddress,
                            out ulong target))
                    {
                        returnValue = GetArm64ConstantReturn(
                            image,
                            executableImage,
                            target,
                            constantReturns);
                    }

                    InvalidateArm64CallerSaved(registers);
                    registers[0] = returnValue;
                    continue;
                }

                if (ArmInstructionDecoder.IsArm64Return(instruction)
                    || ArmInstructionDecoder.TryDecodeArm64UnconditionalBranch(
                        instruction,
                        instructionAddress,
                        out _)
                    || (instruction & 0xFFFFFC1Fu) == 0xD61F0000u)
                {
                    Array.Clear(registers, 0, registers.Length);
                    continue;
                }

                if (TryApplyArm64ValueInstruction(
                        image,
                        executableImage,
                        instruction,
                        instructionAddress,
                        registers,
                        storedFieldValues))
                {
                    continue;
                }

                for (int register = 0; register < registers.Length; register++)
                {
                    if (ArmInstructionDecoder.Arm64WritesRegister(instruction, register))
                        registers[register] = null;
                }
            }
        }
    }

    private static bool TryApplyArm64ValueInstruction(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        uint instruction,
        ulong instructionAddress,
        ulong?[] registers,
        Dictionary<ulong, ulong?>? storedFieldValues = null)
    {
        if (ArmInstructionDecoder.TryDecodeArm64PcRelativeAddress(
                instruction,
                instructionAddress,
                out int destinationRegister,
                out ulong value,
                out _))
        {
            registers[destinationRegister] = value;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64AddImmediate(
                instruction,
                out destinationRegister,
                out int sourceRegister,
                out ulong immediate,
                out _,
                out _))
        {
            registers[destinationRegister] = TryAdd(registers[sourceRegister], immediate);
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64Move(
                instruction,
                out destinationRegister,
                out sourceRegister))
        {
            registers[destinationRegister] = GetArm64Register(registers, sourceRegister);
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64WordExtension(
                instruction,
                out destinationRegister,
                out sourceRegister,
                out bool signExtends))
        {
            ulong? source = registers[sourceRegister];
            registers[destinationRegister] = !source.HasValue
                ? null
                : signExtends
                    ? unchecked((ulong)(long)(int)(uint)source.Value)
                    : (uint)source.Value;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64MoveWide(
                instruction,
                out destinationRegister,
                out value,
                out ulong writeMask,
                out bool keepsOtherBits))
        {
            registers[destinationRegister] = keepsOtherBits
                ? MergeWideValue(registers[destinationRegister], value, writeMask)
                : value;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64MoveBitmaskImmediate(
                instruction,
                out destinationRegister,
                out value))
        {
            registers[destinationRegister] = value;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64ConditionalSelect(
                instruction,
                out destinationRegister,
                out int firstSourceRegister,
                out int secondSourceRegister))
        {
            registers[destinationRegister] = MergeConditionalValues(
                GetArm64Register(registers, firstSourceRegister),
                GetArm64Register(registers, secondSourceRegister));
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm64LiteralAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out ulong literalAddress,
                out int pointerSize)
            && ArmExecutableImageReader.TryMapVirtualRange(
                executableImage,
                literalAddress,
                checked((ulong)pointerSize),
                out ulong literalOffset)
            && ArmExecutableImageReader.TryReadPointer(
                image,
                literalOffset,
                pointerSize,
                out value))
        {
            registers[destinationRegister] = value;
            return true;
        }

        if (storedFieldValues is not null
            && ArmInstructionDecoder.TryDecodeArm64UnsignedImmediateTransfer(
                instruction,
                out destinationRegister,
                out _,
                out ulong fieldOffset,
                out bool isLoad)
            && isLoad)
        {
            storedFieldValues.TryGetValue(fieldOffset, out ulong? fieldValue);
            registers[destinationRegister] = fieldValue;
            return true;
        }

        return false;
    }

    private static Dictionary<ulong, ulong?> CollectArm64StoredFieldValues(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage)
    {
        var values = new Dictionary<ulong, ulong?>();
        var registers = new ulong?[31];
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            ulong firstOffset = (4 - (segment.VirtualAddress & 3)) & 3;
            for (ulong localOffset = firstOffset;
                 localOffset + sizeof(uint) <= segment.FileSize;
                 localOffset += sizeof(uint))
            {
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)(segment.FileOffset + localOffset)), sizeof(uint)));
                ulong instructionAddress = segment.VirtualAddress + localOffset;
                if (ArmInstructionDecoder.TryDecodeArm64UnsignedImmediateTransfer(
                        instruction,
                        out int valueRegister,
                        out _,
                        out ulong fieldOffset,
                        out bool isLoad)
                    && !isLoad
                    && registers[valueRegister].HasValue
                    && IsPlausiblePayloadSize(registers[valueRegister]!.Value))
                {
                    AddUniqueFieldValue(values, fieldOffset, registers[valueRegister]);
                }

                if (ArmInstructionDecoder.IsArm64Call(instruction))
                {
                    InvalidateArm64CallerSaved(registers);
                    continue;
                }

                if (ArmInstructionDecoder.IsArm64Return(instruction)
                    || ArmInstructionDecoder.TryDecodeArm64UnconditionalBranch(
                        instruction,
                        instructionAddress,
                        out _)
                    || (instruction & 0xFFFFFC1Fu) == 0xD61F0000u)
                {
                    Array.Clear(registers, 0, registers.Length);
                    continue;
                }

                if (TryApplyArm64ValueInstruction(
                        image,
                        executableImage,
                        instruction,
                        instructionAddress,
                        registers))
                {
                    continue;
                }

                for (int register = 0; register < registers.Length; register++)
                {
                    if (ArmInstructionDecoder.Arm64WritesRegister(instruction, register))
                        registers[register] = null;
                }
            }
        }

        return values;
    }

    private static ulong? GetArm64ConstantReturn(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ulong target,
        Dictionary<ulong, ulong?> cache)
    {
        if (cache.TryGetValue(target, out ulong? cached))
            return cached;

        ulong? result = TryReadArm64ConstantReturn(image, executableImage, target);
        cache[target] = result;
        return result;
    }

    private static ulong? TryReadArm64ConstantReturn(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ulong target)
    {
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                executableImage,
                target,
                out ulong fileOffset,
                out ulong available))
        {
            return null;
        }

        var registers = new ulong?[31];
        int instructionCount = Math.Min(
            MaximumConstantReturnInstructions,
            checked((int)Math.Min(available / sizeof(uint), int.MaxValue)));
        for (int index = 0; index < instructionCount; index++)
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)(fileOffset + (ulong)(index * sizeof(uint)))), sizeof(uint)));
            ulong instructionAddress = target + checked((ulong)(index * sizeof(uint)));
            if (ArmInstructionDecoder.IsArm64Return(instruction))
                return registers[0];
            if (ArmInstructionDecoder.IsArm64Call(instruction)
                || ArmInstructionDecoder.IsArm64ControlFlowBoundary(instruction))
            {
                return null;
            }

            if (TryApplyArm64ValueInstruction(
                    image,
                    executableImage,
                    instruction,
                    instructionAddress,
                    registers))
            {
                continue;
            }

            for (int register = 0; register < registers.Length; register++)
            {
                if (ArmInstructionDecoder.Arm64WritesRegister(instruction, register))
                    registers[register] = null;
            }
        }

        return null;
    }

    private static void CollectArm32Candidates(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        HashSet<ulong> supportedAddresses,
        HashSet<ulong> nakAddresses,
        Dictionary<ulong, int> candidates,
        Dictionary<ulong, ulong?> constantReturns)
    {
        var registers = new ulong?[15];
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            ulong firstOffset = (4 - (segment.VirtualAddress & 3)) & 3;
            for (ulong localOffset = firstOffset;
                 localOffset + sizeof(uint) <= segment.FileSize;
                 localOffset += sizeof(uint))
            {
                uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(checked((int)(segment.FileOffset + localOffset)), sizeof(uint)));
                ulong instructionAddress = segment.VirtualAddress + localOffset;
                if (ArmInstructionDecoder.IsArm32Call(instruction))
                {
                    CollectCallCandidate(
                        registers,
                        supportedAddresses,
                        nakAddresses,
                        candidates);
                    ulong? returnValue = null;
                    if (ArmInstructionDecoder.TryDecodeArm32DirectCall(
                            instruction,
                            instructionAddress,
                            out ulong target))
                    {
                        returnValue = GetArm32ConstantReturn(
                            image,
                            executableImage,
                            target,
                            constantReturns);
                    }

                    InvalidateArm32CallerSaved(registers);
                    registers[0] = returnValue;
                    continue;
                }

                if (ArmInstructionDecoder.IsArm32Return(instruction)
                    || IsUnconditionalArm32Branch(instruction)
                    || (instruction & 0x0FFFFFF0u) == 0x012FFF10u)
                {
                    Array.Clear(registers, 0, registers.Length);
                    continue;
                }

                if (TryApplyArm32ValueInstruction(
                        image,
                        executableImage,
                        instruction,
                        instructionAddress,
                        registers))
                {
                    CollectRegisterProximityCandidate(
                        registers,
                        supportedAddresses,
                        candidates);
                    continue;
                }

                for (int register = 0; register < registers.Length; register++)
                {
                    if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                        registers[register] = null;
                }
                CollectRegisterProximityCandidate(
                    registers,
                    supportedAddresses,
                    candidates);
            }
        }
    }

    private static bool TryApplyArm32ValueInstruction(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        uint instruction,
        ulong instructionAddress,
        ulong?[] registers)
    {
        if (ArmInstructionDecoder.TryDecodeArm32LiteralAddress(
                instruction,
                instructionAddress,
                out int destinationRegister,
                out ulong literalAddress)
            && ArmExecutableImageReader.TryMapVirtualRange(
                executableImage,
                literalAddress,
                sizeof(uint),
                out ulong literalOffset)
            && ArmExecutableImageReader.TryReadPointer(
                image,
                literalOffset,
                sizeof(uint),
                out ulong value))
        {
            registers[destinationRegister] = value;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm32MoveImmediate(
                instruction,
                out destinationRegister,
                out uint immediateValue))
        {
            registers[destinationRegister] = immediateValue;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm32Move(
                instruction,
                out destinationRegister,
                out int sourceRegister))
        {
            registers[destinationRegister] = GetArm32Register(registers, sourceRegister);
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm32MoveWide(
                instruction,
                out destinationRegister,
                out immediateValue,
                out bool isHighHalf))
        {
            registers[destinationRegister] = isHighHalf
                ? MergeWideValue(
                    registers[destinationRegister],
                    (ulong)immediateValue << 16,
                    0xFFFF0000)
                : immediateValue;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeArm32ImmediateAddress(
                instruction,
                instructionAddress,
                out destinationRegister,
                out sourceRegister,
                out int opcode,
                out immediateValue))
        {
            ulong? source = sourceRegister == 15
                ? instructionAddress + 8
                : GetArm32Register(registers, sourceRegister);
            registers[destinationRegister] = opcode == 4
                ? TryAdd(source, immediateValue)
                : TrySubtract(source, immediateValue);
            return true;
        }

        return false;
    }

    private static void CollectThumbCandidates(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        HashSet<ulong> supportedAddresses,
        HashSet<ulong> nakAddresses,
        Dictionary<ulong, int> candidates,
        Dictionary<ulong, ulong?> constantReturns)
    {
        var registers = new ulong?[15];
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            Array.Clear(registers, 0, registers.Length);
            ulong localOffset = (2 - (segment.VirtualAddress & 1)) & 1;
            while (localOffset + sizeof(ushort) <= segment.FileSize)
            {
                ulong fileOffset = segment.FileOffset + localOffset;
                ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(checked((int)fileOffset), sizeof(ushort)));
                int instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
                if (localOffset + checked((ulong)instructionSize) > segment.FileSize)
                    break;
                ushort second = instructionSize == sizeof(uint)
                    ? BinaryPrimitives.ReadUInt16LittleEndian(
                        image.Slice(checked((int)(fileOffset + sizeof(ushort))), sizeof(ushort)))
                    : (ushort)0;
                ulong instructionAddress = segment.VirtualAddress + localOffset;

                bool isCall = instructionSize == sizeof(uint)
                              && ArmInstructionDecoder.IsThumbBranchLink(first, second)
                              || ArmInstructionDecoder.IsThumbRegisterCall(first);
                if (isCall)
                {
                    CollectCallCandidate(
                        registers,
                        supportedAddresses,
                        nakAddresses,
                        candidates);
                    ulong? returnValue = null;
                    if (instructionSize == sizeof(uint)
                        && ArmInstructionDecoder.TryDecodeThumbDirectCall(
                            first,
                            second,
                            instructionAddress,
                            out ulong target))
                    {
                        returnValue = GetArm32ConstantReturn(
                            image,
                            executableImage,
                            target,
                            constantReturns);
                    }

                    InvalidateArm32CallerSaved(registers);
                    registers[0] = returnValue;
                    localOffset += checked((ulong)instructionSize);
                    continue;
                }

                if (ArmInstructionDecoder.IsThumbReturn(first)
                    || IsUnconditionalThumbBranch(first, second, instructionSize)
                    || (first & 0xFF87) == 0x4700)
                {
                    Array.Clear(registers, 0, registers.Length);
                    localOffset += checked((ulong)instructionSize);
                    continue;
                }

                if (!TryApplyThumbValueInstruction(
                        image,
                        executableImage,
                        first,
                        second,
                        instructionSize,
                        instructionAddress,
                        registers))
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

                CollectRegisterProximityCandidate(
                    registers,
                    supportedAddresses,
                    candidates);

                localOffset += checked((ulong)instructionSize);
            }
        }
    }

    private static bool TryApplyThumbValueInstruction(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ushort first,
        ushort second,
        int instructionSize,
        ulong instructionAddress,
        ulong?[] registers)
    {
        if (ArmInstructionDecoder.TryDecodeThumbAddress(
                first,
                second,
                instructionAddress,
                out int destinationRegister,
                out ulong value,
                out int decodedSize,
                out bool isLiteral)
            && decodedSize == instructionSize)
        {
            if (isLiteral
                && (!ArmExecutableImageReader.TryMapVirtualRange(
                    executableImage,
                    value,
                    sizeof(uint),
                    out ulong literalOffset)
                    || !ArmExecutableImageReader.TryReadPointer(
                        image,
                        literalOffset,
                        sizeof(uint),
                        out value)))
            {
                registers[destinationRegister] = null;
                return true;
            }

            registers[destinationRegister] = value;
            return true;
        }

        if (instructionSize == sizeof(ushort) && (first & 0xF800) == 0x2000)
        {
            destinationRegister = (first >> 8) & 7;
            registers[destinationRegister] = (ulong)(first & 0xFF);
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                first,
                second,
                out destinationRegister,
                out uint immediate,
                out bool isHighHalf))
        {
            registers[destinationRegister] = isHighHalf
                ? MergeWideValue(
                    registers[destinationRegister],
                    (ulong)immediate << 16,
                    0xFFFF0000)
                : immediate;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
                first,
                second,
                out destinationRegister,
                out immediate))
        {
            registers[destinationRegister] = immediate;
            return true;
        }

        if (instructionSize == sizeof(ushort)
            && ArmInstructionDecoder.TryDecodeThumbMove(
                first,
                out destinationRegister,
                out int sourceRegister))
        {
            registers[destinationRegister] = GetArm32Register(registers, sourceRegister);
            return true;
        }

        if (instructionSize == sizeof(ushort)
            && ArmInstructionDecoder.TryDecodeThumbLogicalShiftLeftImmediate(
                first,
                out destinationRegister,
                out int shiftSourceRegister,
                out int shift))
        {
            ulong? source = GetArm32Register(registers, shiftSourceRegister);
            registers[destinationRegister] = source.HasValue
                                             && source.Value <= uint.MaxValue >> shift
                ? (uint)source.Value << shift
                : null;
            return true;
        }

        if (ArmInstructionDecoder.TryDecodeThumbAddSubtractImmediate(
                first,
                second,
                out destinationRegister,
                out sourceRegister,
                out immediate,
                out bool subtracts))
        {
            if (destinationRegister >= registers.Length)
                return true;
            ulong? source = GetArm32Register(registers, sourceRegister);
            registers[destinationRegister] = subtracts
                ? TrySubtract(source, immediate)
                : TryAdd(source, immediate);
            return true;
        }

        return false;
    }

    private static void CollectThumbAddressProximityCandidates(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        HashSet<ulong> supportedAddresses,
        Dictionary<ulong, int> candidates)
    {
        const ulong lookbehindBytes = 64;
        for (int segmentIndex = 0; segmentIndex < executableImage.Segments.Count; segmentIndex++)
        {
            ArmExecutableSegment segment = executableImage.Segments[segmentIndex];
            if (!segment.IsExecutable)
                continue;

            ulong firstOffset = (2 - (segment.VirtualAddress & 1)) & 1;
            for (ulong localOffset = firstOffset;
                 localOffset + sizeof(uint) <= segment.FileSize;
                 localOffset += sizeof(ushort))
            {
                ulong fileOffset = segment.FileOffset + localOffset;
                ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(checked((int)fileOffset), sizeof(ushort)));
                ushort second = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(
                        checked((int)(fileOffset + sizeof(ushort))),
                        sizeof(ushort)));
                ulong instructionAddress = segment.VirtualAddress + localOffset;
                if (!ArmInstructionDecoder.TryDecodeThumbAddress(
                        first,
                        second,
                        instructionAddress,
                        out _,
                        out ulong address,
                        out _,
                        out bool isLiteral)
                    || isLiteral
                    || !supportedAddresses.Contains(address))
                {
                    continue;
                }


                ulong windowStart = localOffset > lookbehindBytes
                    ? localOffset - lookbehindBytes
                    : firstOffset;
                windowStart = (windowStart + 1) & ~1UL;
                ulong candidate = FindThumbWindowPayloadCandidate(
                    image,
                    segment,
                    windowStart,
                    localOffset);
                if (candidate == 0)
                    continue;

                candidates.TryGetValue(candidate, out int count);
                candidates[candidate] = count + 1;
            }
        }
    }

    private static ulong FindThumbWindowPayloadCandidate(
        ReadOnlySpan<byte> image,
        ArmExecutableSegment segment,
        ulong startOffset,
        ulong endOffset)
    {
        var registers = new ulong?[15];
        ulong candidate = 0;
        for (ulong localOffset = startOffset;
             localOffset + sizeof(uint) <= segment.FileSize && localOffset <= endOffset;
             localOffset += sizeof(ushort))
        {
            ulong fileOffset = segment.FileOffset + localOffset;
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)fileOffset), sizeof(ushort)));
            ushort second = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(
                    checked((int)(fileOffset + sizeof(ushort))),
                    sizeof(ushort)));

            if (ArmInstructionDecoder.TryDecodeThumbMoveWide(
                    first,
                    second,
                    out int destinationRegister,
                    out uint immediate,
                    out bool isHighHalf))
            {
                registers[destinationRegister] = isHighHalf
                    ? MergeWideValue(
                        registers[destinationRegister],
                        (ulong)immediate << 16,
                        0xFFFF0000)
                    : immediate;
            }
            else if (ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
                         first,
                         second,
                         out destinationRegister,
                         out immediate))
            {
                registers[destinationRegister] = immediate;
            }
            else if ((first & 0xF800) == 0x2000)
            {
                destinationRegister = (first >> 8) & 7;
                registers[destinationRegister] = (ulong)(first & 0xFF);
            }
            else if (ArmInstructionDecoder.TryDecodeThumbLogicalShiftLeftImmediate(
                         first,
                         out destinationRegister,
                         out int sourceRegister,
                         out int shift)
                     && registers[sourceRegister].HasValue
                     && registers[sourceRegister]!.Value <= uint.MaxValue >> shift)
            {
                registers[destinationRegister] =
                    (uint)registers[sourceRegister]!.Value << shift;
            }

            for (int register = 0; register < registers.Length; register++)
            {
                ulong? value = registers[register];
                if (value.HasValue
                    && value.Value > candidate
                    && IsPlausiblePayloadSize(value.Value))
                {
                    candidate = value.Value;
                }
            }
        }

        return candidate;
    }

    private static ulong? GetArm32ConstantReturn(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ulong target,
        Dictionary<ulong, ulong?> cache)
    {
        if (cache.TryGetValue(target, out ulong? cached))
            return cached;

        ulong? result = (target & 1) != 0
            ? TryReadThumbConstantReturn(image, executableImage, target & ~1UL)
            : TryReadArm32ConstantReturn(image, executableImage, target);
        cache[target] = result;
        return result;
    }

    private static ulong? TryReadArm32ConstantReturn(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ulong target)
    {
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                executableImage,
                target,
                out ulong fileOffset,
                out ulong available))
        {
            return null;
        }

        var registers = new ulong?[15];
        int instructionCount = Math.Min(
            MaximumConstantReturnInstructions,
            checked((int)Math.Min(available / sizeof(uint), int.MaxValue)));
        for (int index = 0; index < instructionCount; index++)
        {
            uint instruction = BinaryPrimitives.ReadUInt32LittleEndian(
                image.Slice(checked((int)(fileOffset + (ulong)(index * sizeof(uint)))), sizeof(uint)));
            ulong instructionAddress = target + checked((ulong)(index * sizeof(uint)));
            if (ArmInstructionDecoder.IsArm32Return(instruction))
                return registers[0];
            if (ArmInstructionDecoder.IsArm32Call(instruction)
                || ArmInstructionDecoder.IsArm32ControlFlowBoundary(instruction))
            {
                return null;
            }

            if (TryApplyArm32ValueInstruction(
                    image,
                    executableImage,
                    instruction,
                    instructionAddress,
                    registers))
            {
                continue;
            }

            for (int register = 0; register < registers.Length; register++)
            {
                if (ArmInstructionDecoder.Arm32WritesRegister(instruction, register))
                    registers[register] = null;
            }
        }

        return null;
    }

    private static ulong? TryReadThumbConstantReturn(
        ReadOnlySpan<byte> image,
        ArmExecutableImage executableImage,
        ulong target)
    {
        if (!ArmExecutableImageReader.TryMapVirtualAddress(
                executableImage,
                target,
                out ulong fileOffset,
                out ulong available))
        {
            return null;
        }

        var registers = new ulong?[15];
        ulong consumed = 0;
        for (int index = 0;
             index < MaximumConstantReturnInstructions && consumed + sizeof(ushort) <= available;
             index++)
        {
            ushort first = BinaryPrimitives.ReadUInt16LittleEndian(
                image.Slice(checked((int)(fileOffset + consumed)), sizeof(ushort)));
            int instructionSize = ArmInstructionDecoder.GetThumbInstructionSize(first);
            if (consumed + checked((ulong)instructionSize) > available)
                return null;
            ushort second = instructionSize == sizeof(uint)
                ? BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(
                        checked((int)(fileOffset + consumed + sizeof(ushort))),
                        sizeof(ushort)))
                : (ushort)0;
            ulong instructionAddress = target + consumed;
            if (ArmInstructionDecoder.IsThumbReturn(first))
                return registers[0];
            if (ArmInstructionDecoder.IsThumbBranchLink(first, second)
                || ArmInstructionDecoder.IsThumbRegisterCall(first)
                || ArmInstructionDecoder.IsThumbControlFlowBoundary(
                    first,
                    second,
                    instructionSize))
            {
                return null;
            }

            if (!TryApplyThumbValueInstruction(
                    image,
                    executableImage,
                    first,
                    second,
                    instructionSize,
                    instructionAddress,
                    registers))
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

            consumed += checked((ulong)instructionSize);
        }

        return null;
    }

    private static void CollectCallCandidate(
        ulong?[] registers,
        HashSet<ulong> supportedAddresses,
        HashSet<ulong> nakAddresses,
        Dictionary<ulong, int> candidates)
    {
        ulong? formatAddress = registers[1];
        ulong? candidate = null;
        if (formatAddress.HasValue && supportedAddresses.Contains(formatAddress.Value))
            candidate = registers[2];
        else if (registers.Length > 3
                 && registers[2].HasValue
                 && supportedAddresses.Contains(registers[2]!.Value))
        {
            candidate = registers[3];
        }
        else if (formatAddress.HasValue && nakAddresses.Contains(formatAddress.Value))
            candidate = registers[3];

        if (!candidate.HasValue || !IsPlausiblePayloadSize(candidate.Value))
            return;

        candidates.TryGetValue(candidate.Value, out int count);
        candidates[candidate.Value] = count + 1;
    }

    private static void CollectRegisterProximityCandidate(
        ulong?[] registers,
        HashSet<ulong> supportedAddresses,
        Dictionary<ulong, int> candidates)
    {
        bool hasSupportedAddress = false;
        ulong candidate = 0;
        for (int register = 0; register < registers.Length; register++)
        {
            ulong? value = registers[register];
            if (!value.HasValue)
                continue;
            if (supportedAddresses.Contains(value.Value))
                hasSupportedAddress = true;
            else if (value.Value > candidate && IsPlausiblePayloadSize(value.Value))
                candidate = value.Value;
        }

        if (!hasSupportedAddress || candidate == 0)
            return;

        candidates.TryGetValue(candidate, out int count);
        candidates[candidate] = count + 1;
    }

    private static bool IsPlausiblePayloadSize(ulong value) =>
        value is >= MinimumPlausiblePayloadSize and <= MaximumPlausiblePayloadSize
        && (value & (value - 1)) == 0;

    private static void AddUniqueFieldValue(
        Dictionary<ulong, ulong?> values,
        ulong fieldOffset,
        ulong? value)
    {
        if (!values.TryGetValue(fieldOffset, out ulong? existing))
            values[fieldOffset] = value;
        else if (existing != value)
            values[fieldOffset] = null;
    }

    private static ulong? GetArm64Register(ulong?[] registers, int register) =>
        register == 31 ? 0 : registers[register];

    private static ulong? GetArm32Register(ulong?[] registers, int register) =>
        register < registers.Length ? registers[register] : null;

    private static ulong? MergeConditionalValues(ulong? first, ulong? second)
    {
        if (first == second)
            return first;
        if (first == 0 && second.HasValue)
            return second;
        if (second == 0 && first.HasValue)
            return first;
        return null;
    }

    private static ulong? MergeWideValue(ulong? previous, ulong value, ulong writeMask) =>
        previous.HasValue ? previous.Value & ~writeMask | value & writeMask : null;

    private static ulong? TryAdd(ulong? value, ulong addend) =>
        value.HasValue && value.Value <= ulong.MaxValue - addend
            ? value.Value + addend
            : null;

    private static ulong? TrySubtract(ulong? value, ulong subtrahend) =>
        value.HasValue && value.Value >= subtrahend
            ? value.Value - subtrahend
            : null;

    private static bool IsUnconditionalArm32Branch(uint instruction) =>
        (instruction >> 28) == 0xE && (instruction & 0x0F000000u) == 0x0A000000u;

    private static bool IsUnconditionalThumbBranch(
        ushort first,
        ushort second,
        int instructionSize) =>
        instructionSize == sizeof(ushort) && (first & 0xF800) == 0xE000
        || instructionSize == sizeof(uint)
        && (first & 0xF800) == 0xF000
        && (second & 0xD000) == 0x9000;

    private static void InvalidateArm64CallerSaved(ulong?[] registers)
    {
        for (int register = 0; register <= 18; register++)
            registers[register] = null;
    }

    private static void InvalidateArm32CallerSaved(ulong?[] registers)
    {
        for (int register = 0; register <= 3; register++)
            registers[register] = null;
        registers[12] = null;
        registers[14] = null;
    }
}
