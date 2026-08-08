namespace QcomImageUtils.Utilities;

/// <summary>
/// Stateless instruction decoding shared by the ARM metadata and Firehose scanners.
/// </summary>
internal static class ArmInstructionDecoder
{
    public static bool TryDecodeArm64PcRelativeAddress(
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address,
        out bool isPageAddress)
    {
        uint opcode = instruction & 0x9F000000u;
        isPageAddress = opcode == 0x90000000u;
        destinationRegister = (int)(instruction & 0x1Fu);
        address = 0;
        if ((opcode != 0x90000000u && opcode != 0x10000000u)
            || destinationRegister >= 31)
        {
            destinationRegister = 0;
            isPageAddress = false;
            return false;
        }

        ulong immediate = ((instruction >> 29) & 3u)
                          | (((instruction >> 5) & 0x7FFFFu) << 2);
        long signedImmediate = ArmInstructionMath.SignExtend(immediate, 21);
        if (isPageAddress)
            signedImmediate <<= 12;

        ulong baseAddress = isPageAddress ? instructionAddress & ~0xFFFUL : instructionAddress;
        return ArmInstructionMath.TryAddSigned(baseAddress, signedImmediate, out address);
    }

    public static bool TryDecodeArm64AddImmediate(
        uint instruction,
        out int destinationRegister,
        out int sourceRegister,
        out ulong immediate,
        out bool is64Bit,
        out bool setsFlags)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        sourceRegister = (int)((instruction >> 5) & 0x1Fu);
        immediate = 0;
        is64Bit = (instruction & 0x80000000u) != 0;
        setsFlags = (instruction & 0x20000000u) != 0;
        if ((instruction & 0x1F000000u) != 0x11000000u
            || (instruction & 0x40000000u) != 0
            || destinationRegister >= 31
            || sourceRegister >= 31)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            is64Bit = false;
            setsFlags = false;
            return false;
        }

        uint shift = (instruction >> 22) & 3u;
        if (shift > 1)
            return false;

        immediate = (instruction >> 10) & 0xFFFu;
        if (shift == 1)
            immediate <<= 12;
        return true;
    }

    public static bool TryDecodeArm64Move(
        uint instruction,
        out int destinationRegister,
        out int sourceRegister)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        sourceRegister = (int)((instruction >> 16) & 0x1Fu);
        if ((instruction & 0xFFE0FFE0u) != 0xAA0003E0u
            || destinationRegister >= 31
            || sourceRegister >= 31)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm64ConditionalSelect(
        uint instruction,
        out int destinationRegister,
        out int firstSourceRegister,
        out int secondSourceRegister)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        firstSourceRegister = (int)((instruction >> 5) & 0x1Fu);
        secondSourceRegister = (int)((instruction >> 16) & 0x1Fu);
        if ((instruction & 0x7FE00C00u) != 0x1A800000u
            || destinationRegister >= 31)
        {
            destinationRegister = 0;
            firstSourceRegister = 0;
            secondSourceRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm64WordExtension(
        uint instruction,
        out int destinationRegister,
        out int sourceRegister,
        out bool signExtends)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        sourceRegister = (int)((instruction >> 5) & 0x1Fu);
        uint opcode = instruction & 0xFFFFFC00u;
        signExtends = opcode == 0x93407C00u;
        if ((!signExtends && opcode != 0xD3407C00u)
            || destinationRegister >= 31
            || sourceRegister >= 31)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            signExtends = false;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm64MoveWide(
        uint instruction,
        out int destinationRegister,
        out ulong value,
        out ulong writeMask,
        out bool keepsOtherBits)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        value = 0;
        writeMask = 0;
        keepsOtherBits = false;
        int operation = (int)((instruction >> 29) & 3u);
        bool is64Bit = (instruction & 0x80000000u) != 0;
        int halfword = (int)((instruction >> 21) & 3u);
        if ((instruction & 0x1F800000u) != 0x12800000u
            || operation == 1
            || destinationRegister >= 31
            || (!is64Bit && halfword >= 2))
        {
            destinationRegister = 0;
            return false;
        }

        int shift = halfword * 16;
        ulong widthMask = is64Bit ? ulong.MaxValue : uint.MaxValue;
        ulong immediate = ((ulong)((instruction >> 5) & 0xFFFFu) << shift) & widthMask;
        switch (operation)
        {
            case 0: // MOVN
                value = ~immediate & widthMask;
                writeMask = widthMask;
                return true;
            case 2: // MOVZ
                value = immediate;
                writeMask = widthMask;
                return true;
            case 3: // MOVK
                value = immediate;
                writeMask = (0xFFFFUL << shift) & widthMask;
                if (!is64Bit)
                    writeMask |= 0xFFFFFFFF00000000UL;
                keepsOtherBits = true;
                return true;
            default:
                destinationRegister = 0;
                return false;
        }
    }

    public static bool TryDecodeArm64MoveBitmaskImmediate(
        uint instruction,
        out int destinationRegister,
        out ulong value)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        value = 0;
        bool is64Bit = (instruction & 0x80000000u) != 0;
        int operation = (int)((instruction >> 29) & 3u);
        int sourceRegister = (int)((instruction >> 5) & 0x1Fu);
        uint n = (instruction >> 22) & 1u;
        uint immr = (instruction >> 16) & 0x3Fu;
        uint imms = (instruction >> 10) & 0x3Fu;
        if ((instruction & 0x1F800000u) != 0x12000000u
            || operation != 1
            || sourceRegister != 31
            || destinationRegister >= 31
            || (!is64Bit && n != 0))
        {
            destinationRegister = 0;
            return false;
        }

        uint lengthSource = n << 6 | (~imms & 0x3Fu);
        int length = HighestSetBit(lengthSource);
        if (length < 1)
        {
            destinationRegister = 0;
            return false;
        }

        int elementSize = 1 << length;
        uint levels = checked((uint)elementSize - 1);
        uint setBits = imms & levels;
        if (setBits == levels)
        {
            destinationRegister = 0;
            return false;
        }

        int rotation = checked((int)(immr & levels));
        ulong elementMask = elementSize == 64
            ? ulong.MaxValue
            : (1UL << elementSize) - 1;
        ulong element = setBits == 63
            ? ulong.MaxValue
            : (1UL << checked((int)setBits + 1)) - 1;
        element = RotateRight(element, rotation, elementSize) & elementMask;

        int dataSize = is64Bit ? 64 : 32;
        for (int shift = 0; shift < dataSize; shift += elementSize)
            value |= element << shift;
        return true;
    }

    public static bool TryDecodeArm64CompareImmediate(
        uint instruction,
        out int sourceRegister,
        out int value)
    {
        sourceRegister = 0;
        value = 0;
        if ((instruction & 0x7F000000u) != 0x71000000u
            || (instruction & 0x1Fu) != 31
            || ((instruction >> 22) & 1u) != 0)
        {
            return false;
        }

        sourceRegister = (int)((instruction >> 5) & 0x1Fu);
        value = (int)((instruction >> 10) & 0xFFFu);
        return sourceRegister < 31;
    }

    public static bool TryDecodeArm64LiteralAddress(
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong literalAddress,
        out int pointerSize)
    {
        destinationRegister = (int)(instruction & 0x1Fu);
        literalAddress = 0;
        pointerSize = 0;
        uint opcode = instruction & 0xFF000000u;
        if (opcode == 0x58000000u)
            pointerSize = sizeof(ulong);
        else if (opcode == 0x18000000u)
            pointerSize = sizeof(uint);
        else
        {
            destinationRegister = 0;
            return false;
        }

        if (destinationRegister >= 31)
        {
            destinationRegister = 0;
            pointerSize = 0;
            return false;
        }

        long offset = ArmInstructionMath.SignExtend((instruction >> 5) & 0x7FFFFu, 19) << 2;
        if (!ArmInstructionMath.TryAddSigned(instructionAddress, offset, out literalAddress))
        {
            destinationRegister = 0;
            pointerSize = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm64UnsignedImmediateTransfer(
        uint instruction,
        out int valueRegister,
        out int baseRegister,
        out ulong offset,
        out bool isLoad)
    {
        valueRegister = (int)(instruction & 0x1Fu);
        baseRegister = (int)((instruction >> 5) & 0x1Fu);
        offset = 0;
        isLoad = (instruction & 0x00400000u) != 0;
        uint size = instruction >> 30;
        if ((instruction & 0x3B000000u) != 0x39000000u
            || (instruction & 0x04000000u) != 0
            || size < 2
            || valueRegister >= 31
            || baseRegister >= 31)
        {
            valueRegister = 0;
            baseRegister = 0;
            isLoad = false;
            return false;
        }

        offset = (ulong)((instruction >> 10) & 0xFFFu) << checked((int)size);
        return true;
    }

    public static bool TryDecodeArm32Move(
        uint instruction,
        out int destinationRegister,
        out int sourceRegister)
    {
        destinationRegister = (int)((instruction >> 12) & 0xFu);
        sourceRegister = (int)(instruction & 0xFu);
        if ((instruction >> 28) == 0xFu
            || destinationRegister >= 15
            || (instruction & 0x0FE00FF0u) != 0x01A00000u)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm32MoveImmediate(
        uint instruction,
        out int destinationRegister,
        out uint value)
    {
        destinationRegister = (int)((instruction >> 12) & 0xFu);
        value = 0;
        int opcode = (int)((instruction >> 21) & 0xFu);
        if ((instruction >> 28) == 0xFu
            || destinationRegister >= 15
            || (instruction & 0x0E000000u) != 0x02000000u
            || opcode is not (13 or 15))
        {
            destinationRegister = 0;
            return false;
        }

        value = ArmInstructionMath.DecodeArm32Immediate(instruction);
        if (opcode == 15)
            value = ~value;
        return true;
    }

    public static bool TryDecodeArm32CompareImmediate(
        uint instruction,
        out int sourceRegister,
        out uint value)
    {
        sourceRegister = (int)((instruction >> 16) & 0xFu);
        value = 0;
        if ((instruction >> 28) == 0xFu
            || (instruction & 0x0FF00000u) != 0x03500000u)
        {
            sourceRegister = 0;
            return false;
        }

        value = ArmInstructionMath.DecodeArm32Immediate(instruction);
        return true;
    }

    public static bool TryDecodeArm32LiteralAddress(
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong literalAddress)
    {
        destinationRegister = (int)((instruction >> 12) & 0xFu);
        literalAddress = 0;
        bool valid = (instruction >> 28) != 0xFu
                     && destinationRegister < 15
                     && (instruction & 0x0C000000u) == 0x04000000u
                     && (instruction & 0x02000000u) == 0
                     && (instruction & 0x01000000u) != 0
                     && (instruction & 0x00400000u) == 0
                     && (instruction & 0x00200000u) == 0
                     && (instruction & 0x00100000u) != 0
                     && ((instruction >> 16) & 0xFu) == 15;
        if (!valid
            || instructionAddress > ulong.MaxValue - 8)
        {
            destinationRegister = 0;
            return false;
        }

        long offset = instruction & 0xFFFu;
        if ((instruction & 0x00800000u) == 0)
            offset = -offset;
        return ArmInstructionMath.TryAddSigned(instructionAddress + 8, offset, out literalAddress);
    }

    public static bool TryDecodeArm32MoveWide(
        uint instruction,
        out int destinationRegister,
        out uint immediate,
        out bool isHighHalf)
    {
        destinationRegister = (int)((instruction >> 12) & 0xFu);
        immediate = ((instruction >> 4) & 0xF000u) | (instruction & 0xFFFu);
        uint opcode = instruction & 0x0FF00000u;
        isHighHalf = opcode == 0x03400000u;
        if ((instruction >> 28) == 0xFu
            || destinationRegister >= 15
            || (opcode != 0x03000000u && !isHighHalf))
        {
            destinationRegister = 0;
            immediate = 0;
            isHighHalf = false;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm32ImmediateAddress(
        uint instruction,
        ulong instructionAddress,
        out int destinationRegister,
        out int sourceRegister,
        out int opcode,
        out uint immediate)
    {
        destinationRegister = (int)((instruction >> 12) & 0xFu);
        sourceRegister = (int)((instruction >> 16) & 0xFu);
        opcode = (int)((instruction >> 21) & 0xFu);
        immediate = ArmInstructionMath.DecodeArm32Immediate(instruction);
        if ((instruction >> 28) == 0xFu
            || destinationRegister >= 15
            || (instruction & 0x0E000000u) != 0x02000000u
            || (instruction & 0x00100000u) != 0
            || (opcode != 4 && opcode != 2))
        {
            destinationRegister = 0;
            sourceRegister = 0;
            opcode = 0;
            immediate = 0;
            return false;
        }

        if (sourceRegister == 15)
            return instructionAddress <= ulong.MaxValue - 8;
        return true;
    }

    public static bool TryDecodeThumbAddress(
        ushort first,
        ushort second,
        ulong instructionAddress,
        out int destinationRegister,
        out ulong address,
        out int instructionSize,
        out bool isLiteral)
    {
        destinationRegister = 0;
        address = 0;
        instructionSize = sizeof(ushort);
        isLiteral = false;
        if (instructionAddress > ulong.MaxValue - 4)
            return false;

        ulong pc = (instructionAddress + 4) & ~3UL;
        if ((first & 0xF800) == 0xA000)
        {
            destinationRegister = (first >> 8) & 7;
            ulong immediate = (ulong)(first & 0xFF) << 2;
            return pc <= ulong.MaxValue - immediate &&
                   ArmInstructionMath.TryAddSigned(pc, (long)immediate, out address);
        }

        if ((first & 0xF800) == 0x4800)
        {
            destinationRegister = (first >> 8) & 7;
            ulong immediate = (ulong)(first & 0xFF) << 2;
            isLiteral = true;
            return pc <= ulong.MaxValue - immediate &&
                   ArmInstructionMath.TryAddSigned(pc, (long)immediate, out address);
        }

        if ((first & 0xFF7F) == 0xF85F)
        {
            instructionSize = sizeof(uint);
            destinationRegister = (second >> 12) & 0xF;
            isLiteral = true;
            if (destinationRegister >= 15)
                return false;

            long offset = second & 0x0FFF;
            if ((first & 0x0080) == 0)
                offset = -offset;
            return ArmInstructionMath.TryAddSigned(pc, offset, out address);
        }

        bool isAdd = (first & 0xFBF0) == 0xF200 && (first & 0xF) == 0xF;
        bool isSubtract = (first & 0xFBF0) == 0xF2A0 && (first & 0xF) == 0xF;
        if (!isAdd && !isSubtract)
            return false;

        instructionSize = sizeof(uint);
        destinationRegister = (second >> 8) & 0xF;
        if (destinationRegister >= 15)
            return false;
        ulong immediateValue = (ulong)((first >> 10) & 1) << 11
                               | (ulong)((second >> 12) & 7) << 8
                               | (uint)(second & 0xFF);
        long signedImmediate = isAdd ? (long)immediateValue : -(long)immediateValue;
        return ArmInstructionMath.TryAddSigned(pc, signedImmediate, out address);
    }

    public static bool TryDecodeThumbMove(
        ushort instruction,
        out int destinationRegister,
        out int sourceRegister)
    {
        destinationRegister = (instruction & 7) | ((instruction >> 4) & 8);
        sourceRegister = (instruction >> 3) & 0xF;
        if ((instruction & 0xFF00) != 0x4600
            || destinationRegister >= 15)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeThumbMoveWide(
        ushort first,
        ushort second,
        out int destinationRegister,
        out uint immediate,
        out bool isHighHalf)
    {
        uint opcode = (uint)first & 0xFBF0u;
        isHighHalf = opcode == 0xF2C0u;
        destinationRegister = (second >> 8) & 0xF;
        if ((opcode != 0xF240u && !isHighHalf)
            || (second & 0x8000) != 0
            || destinationRegister >= 15)
        {
            destinationRegister = 0;
            immediate = 0;
            isHighHalf = false;
            return false;
        }

        immediate = (uint)(first & 0xF) << 12
                    | (uint)((first >> 10) & 1) << 11
                    | (uint)((second >> 12) & 7) << 8
                    | (uint)(second & 0xFF);
        return true;
    }

    public static bool TryDecodeThumbMoveImmediate(
        ushort first,
        ushort second,
        out int destinationRegister,
        out uint value)
    {
        destinationRegister = (second >> 8) & 0xF;
        value = 0;
        if ((first & 0xFBEF) != 0xF04F
            || (second & 0x8000) != 0
            || destinationRegister >= 15)
        {
            destinationRegister = 0;
            return false;
        }

        uint immediate = (uint)((first >> 10) & 1) << 11
                         | (uint)((second >> 12) & 7) << 8
                         | (uint)(second & 0xFF);
        value = DecodeThumbModifiedImmediate(immediate);
        return true;
    }

    public static bool TryDecodeThumbAddSubtractImmediate(
        ushort first,
        ushort second,
        out int destinationRegister,
        out int sourceRegister,
        out uint immediate,
        out bool subtracts)
    {
        uint modifiedOpcode = (uint)first & 0xFBE0u;
        bool isModifiedAdd = modifiedOpcode == 0xF100u;
        bool isModifiedSubtract = modifiedOpcode == 0xF1A0u;
        uint wideOpcode = (uint)first & 0xFBF0u;
        bool isWideAdd = wideOpcode == 0xF200u;
        bool isWideSubtract = wideOpcode == 0xF2A0u;
        subtracts = isModifiedSubtract || isWideSubtract;
        destinationRegister = (second >> 8) & 0xF;
        sourceRegister = first & 0xF;
        immediate = 0;
        if ((!isModifiedAdd
             && !isModifiedSubtract
             && !isWideAdd
             && !isWideSubtract)
            || (second & 0x8000) != 0)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            subtracts = false;
            return false;
        }

        uint encodedImmediate = (uint)((first >> 10) & 1) << 11
                                | (uint)((second >> 12) & 7) << 8
                                | (uint)(second & 0xFF);
        immediate = isModifiedAdd || isModifiedSubtract
            ? DecodeThumbModifiedImmediate(encodedImmediate)
            : encodedImmediate;
        return true;
    }

    public static bool TryDecodeThumbLogicalShiftLeftImmediate(
        ushort instruction,
        out int destinationRegister,
        out int sourceRegister,
        out int shift)
    {
        destinationRegister = instruction & 7;
        sourceRegister = (instruction >> 3) & 7;
        shift = (instruction >> 6) & 0x1F;
        if ((instruction & 0xF800) != 0 || shift == 0)
        {
            destinationRegister = 0;
            sourceRegister = 0;
            shift = 0;
            return false;
        }

        return true;
    }

    public static int GetThumbInstructionSize(ushort first)
    {
        int prefix = first >> 11;
        return prefix is 0x1D or 0x1E or 0x1F
            ? sizeof(uint)
            : sizeof(ushort);
    }

    public static bool ThumbWritesRegister(
        ushort first,
        ushort second,
        int instructionSize,
        int register)
    {
        if ((uint)register >= 16)
            return false;

        if (instructionSize == sizeof(uint))
        {
            if (IsThumbBranchLink(first, second))
                return register == 14;
            if (TryDecodeThumbMoveWide(
                    first,
                    second,
                    out int moveWideDestination,
                    out _,
                    out _))
            {
                return moveWideDestination == register;
            }
            if (TryDecodeThumbMoveImmediate(
                    first,
                    second,
                    out int moveImmediateDestination,
                    out _))
            {
                return moveImmediateDestination == register;
            }
            if (TryDecodeThumbAddSubtractImmediate(
                    first,
                    second,
                    out int arithmeticDestination,
                    out _,
                    out _,
                    out _))
            {
                return arithmeticDestination < 15
                       && arithmeticDestination == register;
            }
            if (TryDecodeThumbWideLoadDestination(
                    first,
                    second,
                    out int loadDestination))
            {
                return loadDestination < 15 && loadDestination == register;
            }
            if (first == 0xF3AF && (second & 0x8F00) == 0x8000)
                return false;
            return true;
        }

        if (TryDecodeThumbMove(first, out int moveDestination, out _))
            return moveDestination == register;

        ushort opcode = (ushort)(first & 0xF800);
        if ((first & 0xE000) == 0)
            return (first & 7) == register;
        if (opcode is 0x2000 or 0x3000 or 0x3800 or 0x4800)
            return ((first >> 8) & 7) == register;

        if ((first & 0xFC00) == 0x4000)
        {
            int operation = (first >> 6) & 0xF;
            return operation is not (8 or 10 or 11)
                   && (first & 7) == register;
        }

        if ((first & 0xFC00) == 0x4400)
        {
            int operation = (first >> 8) & 3;
            int destination = (first & 7) | ((first >> 4) & 8);
            return operation is 0 or 2 && destination == register;
        }

        if ((first & 0xF000) == 0x5000)
        {
            int operation = (first >> 9) & 7;
            return operation >= 3 && (first & 7) == register;
        }

        if (opcode is 0x6800 or 0x7800 or 0x8800)
            return (first & 7) == register;
        if (opcode == 0x9800)
            return ((first >> 8) & 7) == register;
        if ((first & 0xF000) == 0xA000)
            return ((first >> 8) & 7) == register;

        if ((first & 0xFF00) == 0xB000)
            return register == 13;
        if ((first & 0xFF00) is 0xB200 or 0xBA00)
            return (first & 7) == register;
        if ((first & 0xFE00) == 0xB400)
            return register == 13;
        if ((first & 0xFE00) == 0xBC00)
        {
            return register == 13
                   || (register < 8 && ((first >> register) & 1) != 0)
                   || (register == 15 && (first & 0x0100) != 0);
        }

        if ((first & 0xF000) == 0xC000)
        {
            int baseRegister = (first >> 8) & 7;
            bool isLoad = (first & 0x0800) != 0;
            return baseRegister == register
                   || (isLoad && register < 8 && ((first >> register) & 1) != 0);
        }

        return false;
    }

    public static bool TryDecodeArm64DirectCall(
        uint instruction,
        ulong instructionAddress,
        out ulong target)
    {
        if ((instruction & 0xFC000000u) != 0x94000000u)
        {
            target = 0;
            return false;
        }

        long offset = ArmInstructionMath.SignExtend(
            (ulong)(instruction & 0x03FFFFFFu) << 2,
            28);
        return ArmInstructionMath.TryAddSigned(instructionAddress, offset, out target);
    }

    public static bool TryDecodeArm64UnconditionalBranch(
        uint instruction,
        ulong instructionAddress,
        out ulong target)
    {
        if ((instruction & 0xFC000000u) != 0x14000000u)
        {
            target = 0;
            return false;
        }

        long offset = ArmInstructionMath.SignExtend(
            (ulong)(instruction & 0x03FFFFFFu) << 2,
            28);
        return ArmInstructionMath.TryAddSigned(instructionAddress, offset, out target);
    }

    public static bool TryDecodeArm64RegisterCall(
        uint instruction,
        out int targetRegister)
    {
        targetRegister = (int)((instruction >> 5) & 0x1Fu);
        if ((instruction & 0xFFFFFC1Fu) != 0xD63F0000u
            || targetRegister >= 31)
        {
            targetRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeArm32DirectCall(
        uint instruction,
        ulong instructionAddress,
        out ulong target)
    {
        if ((instruction & 0x0F000000u) == 0x0B000000u
            && (instruction >> 28) != 0xFu)
        {
            long offset = ArmInstructionMath.SignExtend(
                (ulong)(instruction & 0x00FFFFFFu) << 2,
                26);
            if (instructionAddress > ulong.MaxValue - 8)
            {
                target = 0;
                return false;
            }

            return ArmInstructionMath.TryAddSigned(
                instructionAddress + 8,
                offset,
                out target);
        }

        if ((instruction & 0xFE000000u) == 0xFA000000u)
        {
            ulong immediate = (ulong)(instruction & 0x00FFFFFFu) << 2
                              | (ulong)((instruction >> 24) & 1u) << 1;
            long offset = ArmInstructionMath.SignExtend(immediate, 26);
            if (instructionAddress > ulong.MaxValue - 8
                || !ArmInstructionMath.TryAddSigned(
                    instructionAddress + 8,
                    offset,
                    out target))
            {
                target = 0;
                return false;
            }

            target |= 1;
            return true;
        }

        target = 0;
        return false;
    }

    public static bool TryDecodeArm32Branch(
        uint instruction,
        ulong instructionAddress,
        out ulong target,
        out bool isLink)
    {
        isLink = (instruction & 0x01000000u) != 0;
        if ((instruction >> 28) == 0xFu
            || (instruction & 0x0E000000u) != 0x0A000000u
            || instructionAddress > ulong.MaxValue - 8)
        {
            target = 0;
            isLink = false;
            return false;
        }

        long offset = ArmInstructionMath.SignExtend(
            (ulong)(instruction & 0x00FFFFFFu) << 2,
            26);
        return ArmInstructionMath.TryAddSigned(
            instructionAddress + 8,
            offset,
            out target);
    }

    public static bool TryDecodeArm32RegisterCall(
        uint instruction,
        out int targetRegister)
    {
        targetRegister = (int)(instruction & 0xFu);
        if ((instruction >> 28) == 0xFu
            || (instruction & 0x0FFFFFF0u) != 0x012FFF30u)
        {
            targetRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeThumbDirectCall(
        ushort first,
        ushort second,
        ulong instructionAddress,
        out ulong target)
    {
        bool isBranchLink = (first & 0xF800) == 0xF000
                            && (second & 0xD000) == 0xD000;
        bool isBranchLinkExchange = (first & 0xF800) == 0xF000
                                    && (second & 0xD001) == 0xC000;
        if (!isBranchLink && !isBranchLinkExchange)
        {
            target = 0;
            return false;
        }

        ulong sign = (ulong)(first >> 10) & 1;
        ulong firstComplement = (~(((ulong)(second >> 13) & 1) ^ sign)) & 1;
        ulong secondComplement = (~(((ulong)(second >> 11) & 1) ^ sign)) & 1;
        ulong immediate = sign << 24
                          | firstComplement << 23
                          | secondComplement << 22
                          | (ulong)(first & 0x03FF) << 12
                          | (ulong)(second & 0x07FF) << 1;
        long signedOffset = ArmInstructionMath.SignExtend(immediate, 25);
        if (instructionAddress > ulong.MaxValue - 4)
        {
            target = 0;
            return false;
        }

        ulong pc = instructionAddress + 4;
        if (isBranchLinkExchange)
            pc &= ~3UL;
        if (!ArmInstructionMath.TryAddSigned(pc, signedOffset, out target))
            return false;

        if (isBranchLink)
            target |= 1;
        return true;
    }

    public static bool TryDecodeThumbRegisterCall(
        ushort instruction,
        out int targetRegister)
    {
        targetRegister = (int)((instruction >> 3) & 0xFu);
        if ((instruction & 0xFF87) != 0x4780
            || targetRegister == 15)
        {
            targetRegister = 0;
            return false;
        }

        return true;
    }

    public static bool TryDecodeThumbUnconditionalBranch(
        ushort first,
        ushort second,
        int instructionSize,
        ulong instructionAddress,
        out ulong target)
    {
        if (instructionAddress > ulong.MaxValue - 4)
        {
            target = 0;
            return false;
        }

        if (instructionSize == sizeof(ushort)
            && (first & 0xF800) == 0xE000)
        {
            long offset = ArmInstructionMath.SignExtend(
                (ulong)(first & 0x07FF) << 1,
                12);
            return ArmInstructionMath.TryAddSigned(
                instructionAddress + 4,
                offset,
                out target);
        }

        if (instructionSize != sizeof(uint)
            || (first & 0xF800) != 0xF000
            || (second & 0xD000) != 0x9000)
        {
            target = 0;
            return false;
        }

        ulong sign = (ulong)(first >> 10) & 1;
        ulong firstComplement = (~(((ulong)(second >> 13) & 1) ^ sign)) & 1;
        ulong secondComplement = (~(((ulong)(second >> 11) & 1) ^ sign)) & 1;
        ulong immediate = sign << 24
                          | firstComplement << 23
                          | secondComplement << 22
                          | (ulong)(first & 0x03FF) << 12
                          | (ulong)(second & 0x07FF) << 1;
        long signedOffset = ArmInstructionMath.SignExtend(immediate, 25);
        return ArmInstructionMath.TryAddSigned(
            instructionAddress + 4,
            signedOffset,
            out target);
    }

    public static bool Arm64WritesRegister(uint instruction, int register)
    {
        if ((uint)register >= 31)
            return false;

        bool writes = false;
        int destination = (int)(instruction & 0x1Fu);
        bool readsSystemRegister = (instruction & 0xFFF00000u) == 0xD5300000u;
        if (readsSystemRegister)
            writes = destination == register;
        uint majorOpcode = (instruction >> 25) & 0xFu;
        bool isConditionalCompare = (instruction & 0x1FE00000u) == 0x1A400000u;
        if (!isConditionalCompare
            && majorOpcode is 0x5 or 0x8 or 0x9 or 0xD
            && destination == register)
        {
            writes = true;
        }

        if ((instruction & 0x3B000000u) == 0x18000000u
            && (instruction & 0x04000000u) == 0
            && ((instruction >> 30) & 3u) != 3u)
        {
            writes |= destination == register;
        }

        uint singleClass = instruction & 0x3B000000u;
        uint loadOpcode = (instruction >> 22) & 3u;
        uint size = instruction >> 30;
        bool integerLoad = singleClass is 0x38000000u or 0x39000000u
                           && (instruction & 0x04000000u) == 0
                           && loadOpcode != 0
                           && !(size == 3 && loadOpcode == 2);
        bool lseAtomic = singleClass == 0x38000000u
                         && ((instruction >> 21) & 1u) != 0
                         && ((instruction >> 10) & 3u) == 0;
        if (integerLoad || lseAtomic)
            writes |= destination == register;

        bool exclusive = (instruction & 0x3F000000u) == 0x08000000u;
        if (exclusive)
        {
            int statusRegister = (int)((instruction >> 16) & 0x1Fu);
            writes |= statusRegister == register;
            if (((instruction >> 22) & 1u) != 0)
            {
                writes |= destination == register;
                if (((instruction >> 21) & 1u) != 0)
                    writes |= ((instruction >> 10) & 0x1Fu) == register;
            }
        }

        bool pair = (instruction & 0x3A000000u) == 0x28000000u;
        if (pair
            && (instruction & 0x04000000u) == 0
            && ((instruction >> 22) & 1u) != 0)
        {
            writes |= destination == register
                      || ((instruction >> 10) & 0x1Fu) == register;
        }

        if (pair && ((instruction >> 23) & 1u) != 0)
            writes |= ((instruction >> 5) & 0x1Fu) == register;

        if (singleClass == 0x38000000u
            && (instruction & 0x00200000u) == 0
            && ((((instruction >> 10) & 3u) & 1u) != 0))
        {
            writes |= ((instruction >> 5) & 0x1Fu) == register;
        }

        return writes;
    }

    public static bool Arm32WritesRegister(uint instruction, int register)
    {
        if ((uint)register >= 16)
            return false;

        bool readsCoprocessorRegister = (instruction & 0x0F100010u) == 0x0E100010u;
        if (readsCoprocessorRegister)
        {
            int targetRegister = (int)((instruction >> 12) & 0xFu);
            return targetRegister < 15 && targetRegister == register;
        }

        bool readsCoprocessorRegisterPair =
            (instruction & 0x0FF00000u) == 0x0C500000u;
        if (readsCoprocessorRegisterPair)
        {
            int firstTargetRegister = (int)((instruction >> 12) & 0xFu);
            int secondTargetRegister = (int)((instruction >> 16) & 0xFu);
            return firstTargetRegister < 15 && firstTargetRegister == register
                   || secondTargetRegister < 15 && secondTargetRegister == register;
        }

        if ((instruction >> 28) == 0xF)
            return false;

        bool countsLeadingZeros = (instruction & 0x0FFF0FF0u) == 0x016F0F10u;
        if (countsLeadingZeros)
            return ((instruction >> 12) & 0xFu) == register;

        if ((instruction & 0x0C000000u) == 0)
        {
            bool readsStatusRegister = (instruction & 0x0FBF0FFFu) == 0x010F0000u;
            if (readsStatusRegister)
                return ((instruction >> 12) & 0xFu) == register;

            bool isSwap = (instruction & 0x0FB00FF0u) == 0x01000090u;
            if (isSwap)
                return ((instruction >> 12) & 0xFu) == register;

            bool isLongMultiply = (instruction & 0x0F8000F0u) == 0x00800090u;
            if (isLongMultiply)
            {
                return ((instruction >> 16) & 0xFu) == register
                       || ((instruction >> 12) & 0xFu) == register;
            }

            bool isMultiply = (instruction & 0x0FC000F0u) == 0x00000090u;
            if (isMultiply)
                return ((instruction >> 16) & 0xFu) == register;

            bool isExtraTransfer = (instruction & 0x0E000090u) == 0x00000090u
                                   && (instruction & 0x60u) != 0;
            if (isExtraTransfer)
            {
                int destination = (int)((instruction >> 12) & 0xFu);
                bool loadsValue = (instruction & 0x00100000u) != 0;
                int transferOperation = (int)((instruction >> 5) & 3u);
                bool loadsDoubleword = !loadsValue && transferOperation == 2;
                bool writesLoadedValue = (loadsValue || loadsDoubleword)
                                         && destination == register;
                bool writesSecondValue = loadsDoubleword
                                         && destination < 14
                                         && destination + 1 == register;
                bool writesBackBase = (((instruction >> 21) & 1u) != 0
                                       || ((instruction >> 24) & 1u) == 0)
                                      && ((instruction >> 16) & 0xFu) == register;
                return writesLoadedValue || writesSecondValue || writesBackBase;
            }

            int opcode = (int)((instruction >> 21) & 0xF);
            return opcode is not (8 or 9 or 10 or 11)
                   && ((instruction >> 12) & 0xFu) == register;
        }

        if ((instruction & 0x0C000000u) == 0x04000000u)
        {
            bool writesLoadedValue = ((instruction >> 20) & 1u) != 0
                                      && ((instruction >> 12) & 0xFu) == register;
            bool writesBackBase = (((instruction >> 21) & 1u) != 0
                                   || ((instruction >> 24) & 1u) == 0)
                                  && ((instruction >> 16) & 0xFu) == register;
            return writesLoadedValue || writesBackBase;
        }

        if ((instruction & 0x0E000000u) == 0x08000000u)
        {
            bool loadsRegister = ((instruction >> 20) & 1u) != 0
                                  && ((instruction >> register) & 1u) != 0;
            bool writesBackBase = ((instruction >> 21) & 1u) != 0
                                  && ((instruction >> 16) & 0xFu) == register;
            return loadsRegister || writesBackBase;
        }

        return false;
    }

    public static bool IsArm64Call(uint instruction)
    {
        return (instruction & 0xFC000000u) == 0x94000000u
               || TryDecodeArm64RegisterCall(instruction, out _);
    }

    public static bool IsArm64ControlFlowBoundary(uint instruction)
    {
        return (instruction & 0xFC000000u) == 0x14000000u
               || (instruction & 0xFF000010u) == 0x54000000u
               || (instruction & 0x7E000000u) == 0x34000000u
               || (instruction & 0x7E000000u) == 0x36000000u
               || (instruction & 0xFFFFFC1Fu) == 0xD61F0000u
               || IsArm64Return(instruction);
    }

    public static bool IsArm64Return(uint instruction)
    {
        return (instruction & 0xFFFFFC1Fu) == 0xD65F0000u;
    }

    public static bool IsArm32Call(uint instruction)
    {
        return (instruction & 0x0F000000u) == 0x0B000000u
               || TryDecodeArm32RegisterCall(instruction, out _)
               || (instruction & 0xFE000000u) == 0xFA000000u;
    }

    public static bool IsArm32ControlFlowBoundary(uint instruction)
    {
        return (instruction & 0x0F000000u) == 0x0A000000u
               || (instruction & 0x0FFFFFF0u) == 0x012FFF10u
               || (!IsArm32Call(instruction)
                   && Arm32WritesRegister(instruction, 15))
               || IsArm32Return(instruction);
    }

    public static bool IsArm32Return(uint instruction)
    {
        return (instruction >> 28) != 0xFu
               && ((instruction & 0x0FFFFFFFu) == 0x012FFF1Eu
                   || (instruction & 0x0FFF8000u) == 0x08BD8000u
                   || (instruction & 0x0FFFFFFFu) == 0x01A0F00Eu);
    }

    public static bool IsThumbBranchLink(ushort first, ushort second)
    {
        return (first & 0xF800) == 0xF000
               && ((second & 0xD000) == 0xD000
                   || (second & 0xD001) == 0xC000);
    }

    public static bool IsThumbRegisterCall(ushort instruction)
    {
        return TryDecodeThumbRegisterCall(instruction, out _);
    }

    public static bool IsThumbControlFlowBoundary(ushort instruction)
    {
        return (instruction & 0xF800) == 0xE000
               || (instruction & 0xF000) == 0xD000
               || (instruction & 0xF500) == 0xB100
               || ((instruction & 0xFF00) == 0x4700
                   && !IsThumbRegisterCall(instruction))
               || (instruction & 0xFF87) is 0x4487 or 0x4687
               || IsThumbReturn(instruction);
    }

    public static bool IsThumbControlFlowBoundary(
        ushort first,
        ushort second,
        int instructionSize)
    {
        if (IsThumbControlFlowBoundary(first))
            return true;
        if (instructionSize != sizeof(uint)
            || (first & 0xF800) != 0xF000)
        {
            return false;
        }

        uint secondOpcode = (uint)second & 0xD000u;
        bool conditionalBranch = secondOpcode == 0x8000u
                                 && ((first >> 6) & 0xFu) < 0xEu;
        bool unconditionalBranch = secondOpcode == 0x9000u;
        return conditionalBranch || unconditionalBranch;
    }

    public static bool IsThumbReturn(ushort instruction)
    {
        return instruction == 0x4770
               || (instruction & 0xFF00) == 0xBD00;
    }

    private static uint DecodeThumbModifiedImmediate(uint immediate)
    {
        uint lowByte = immediate & 0xFFu;
        if ((immediate & 0xC00u) == 0)
        {
            return ((immediate >> 8) & 3u) switch
            {
                0 => lowByte,
                1 => lowByte | lowByte << 16,
                2 => lowByte << 8 | lowByte << 24,
                _ => lowByte * 0x01010101u
            };
        }

        uint unrotated = 0x80u | (immediate & 0x7Fu);
        return ArmInstructionMath.RotateRight(unrotated, (int)((immediate >> 7) & 0x1Fu));
    }

    private static int HighestSetBit(uint value)
    {
        for (int bit = 31; bit >= 0; bit--)
        {
            if ((value & 1u << bit) != 0)
                return bit;
        }

        return -1;
    }

    private static ulong RotateRight(ulong value, int rotation, int width)
    {
        rotation %= width;
        if (rotation == 0)
            return value;
        return value >> rotation | value << (width - rotation);
    }

    private static bool TryDecodeThumbWideLoadDestination(
        ushort first,
        ushort second,
        out int destinationRegister)
    {
        destinationRegister = (second >> 12) & 0xF;
        ushort opcode = (ushort)(first & 0xFFF0);
        if (opcode is 0xF890 or 0xF8B0 or 0xF8D0 or 0xF990 or 0xF9B0)
            return true;

        // Register-offset LDR.W has no base writeback in this encoding.
        return opcode == 0xF850 && (second & 0x0FC0) == 0;
    }
}
