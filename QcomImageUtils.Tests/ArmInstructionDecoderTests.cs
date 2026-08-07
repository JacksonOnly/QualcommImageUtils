using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class ArmInstructionDecoderTests
{
    [Fact]
    public void Arm32WritesRegister_Multiply_WritesOnlyDestination()
    {
        const uint instruction = 0xE0040291u; // MUL r4, r1, r2

        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(instruction, 4));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(instruction, 0));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(instruction, 1));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(instruction, 2));
    }

    [Fact]
    public void Arm32WritesRegister_LongMultiply_WritesBothDestinations()
    {
        const uint instruction = 0xE0854291u; // UMULL r4, r5, r1, r2

        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(instruction, 4));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(instruction, 5));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(instruction, 1));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(instruction, 2));
    }

    [Theory]
    [InlineData(0xE4932004u, true)]
    [InlineData(0xE4832004u, false)]
    public void Arm32WritesRegister_PostIndexedTransfer_WritesBackBase(
        uint instruction,
        bool loadsValue)
    {
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(instruction, 3));
        Assert.Equal(
            loadsValue,
            ArmInstructionDecoder.Arm32WritesRegister(instruction, 2));
    }

    [Fact]
    public void Arm64WritesRegister_Mrs_WritesDestination()
    {
        const uint instruction = 0xD53BD040u; // MRS X0, TPIDR_EL0

        Assert.True(ArmInstructionDecoder.Arm64WritesRegister(instruction, 0));
        Assert.False(ArmInstructionDecoder.Arm64WritesRegister(instruction, 1));
    }

    [Fact]
    public void Arm32WritesRegister_MrsAndLdrh_WriteDestination()
    {
        const uint mrs = 0xE10F0000u; // MRS R0, CPSR
        const uint loadHalfword = 0xE1D100B0u; // LDRH R0, [R1]

        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrs, 0));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(mrs, 1));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(loadHalfword, 0));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(loadHalfword, 1));
    }

    [Fact]
    public void Arm32WritesRegister_CoprocessorReadsAndClz_WriteDestinations()
    {
        const uint mrc = 0xEE100F10u; // MRC p15, 0, R0, c0, c0, 0
        const uint mrrc = 0xEC510F00u; // MRRC p15, 0, R0, R1, c0
        const uint clz = 0xE16F0F11u; // CLZ R0, R1

        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrc, 0));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(mrc, 1));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrrc, 0));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrrc, 1));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(mrrc, 2));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(clz, 0));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(clz, 1));
    }

    [Fact]
    public void Arm32WritesRegister_UnconditionalCoprocessorReads_WriteGprsOnly()
    {
        const uint mrc2 = 0xFE100F10u; // MRC2 p15, 0, R0, c0, c0, 0
        const uint mrrc2 = 0xFC510F00u; // MRRC2 p15, 0, R0, R1, c0
        const uint mrcToApsr = 0xEE10FF10u; // MRC p15, 0, APSR_nzcv, c0, c0, 0

        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrc2, 0));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrrc2, 0));
        Assert.True(ArmInstructionDecoder.Arm32WritesRegister(mrrc2, 1));
        Assert.False(ArmInstructionDecoder.Arm32WritesRegister(mrcToApsr, 15));
        Assert.False(ArmInstructionDecoder.IsArm32ControlFlowBoundary(mrcToApsr));
    }

    [Fact]
    public void TryDecodeThumbMoveImmediate_MovWide_ReturnsOnlyDestination()
    {
        bool decoded = ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
            0xF04F,
            0x0004,
            out int destinationRegister,
            out uint value);

        Assert.True(decoded);
        Assert.Equal(0, destinationRegister);
        Assert.Equal(4U, value);
        Assert.True(ArmInstructionDecoder.ThumbWritesRegister(0xF04F, 0x0004, 4, 0));
        Assert.False(ArmInstructionDecoder.ThumbWritesRegister(0xF04F, 0x0004, 4, 1));
    }

    [Fact]
    public void ThumbWritesRegister_AddWideAndLoadWide_ReturnOnlyDestinations()
    {
        Assert.True(ArmInstructionDecoder.ThumbWritesRegister(0xF100, 0x0004, 4, 0));
        Assert.False(ArmInstructionDecoder.ThumbWritesRegister(0xF100, 0x0004, 4, 1));
        Assert.True(ArmInstructionDecoder.ThumbWritesRegister(0xF8D1, 0x0004, 4, 0));
        Assert.False(ArmInstructionDecoder.ThumbWritesRegister(0xF8D1, 0x0004, 4, 1));
    }

    [Theory]
    [InlineData(0xF500, 0x3080, 0, 0, 0x10000)]
    [InlineData(0xF201, 0x1100, 1, 1, 0x100)]
    public void TryDecodeThumbAddSubtractImmediate_ExpandsModifiedAndWideValues(
        ushort first,
        ushort second,
        int expectedDestination,
        int expectedSource,
        uint expectedImmediate)
    {
        bool decoded = ArmInstructionDecoder.TryDecodeThumbAddSubtractImmediate(
            first,
            second,
            out int destinationRegister,
            out int sourceRegister,
            out uint immediate,
            out bool subtracts);

        Assert.True(decoded);
        Assert.Equal(expectedDestination, destinationRegister);
        Assert.Equal(expectedSource, sourceRegister);
        Assert.Equal(expectedImmediate, immediate);
        Assert.False(subtracts);
    }

    [Fact]
    public void TryDecodeArm64MoveWide_WRegisterMoveKeep_ClearsUpperHalf()
    {
        const uint instruction = 0x72A24680u; // MOVK W0, #0x1234, LSL #16

        bool decoded = ArmInstructionDecoder.TryDecodeArm64MoveWide(
            instruction,
            out int destinationRegister,
            out ulong value,
            out ulong writeMask,
            out bool keepsOtherBits);

        Assert.True(decoded);
        Assert.Equal(0, destinationRegister);
        Assert.Equal(0x12340000UL, value);
        Assert.Equal(0xFFFFFFFFFFFF0000UL, writeMask);
        Assert.True(keepsOtherBits);
    }

    [Fact]
    public void TryDecodeArm32MoveImmediate_MovAndMvn_ReturnValues()
    {
        Assert.True(ArmInstructionDecoder.TryDecodeArm32MoveImmediate(
            0xE3A01602u,
            out int moveDestination,
            out uint moveValue));
        Assert.Equal(1, moveDestination);
        Assert.Equal(0x00200000u, moveValue);

        Assert.True(ArmInstructionDecoder.TryDecodeArm32MoveImmediate(
            0xE3E00000u,
            out int moveNotDestination,
            out uint moveNotValue));
        Assert.Equal(0, moveNotDestination);
        Assert.Equal(uint.MaxValue, moveNotValue);
    }

    [Fact]
    public void ThumbCallPredicates_RecognizeRegisterAndImmediateBlx()
    {
        const ushort registerBlx = 0x47A0; // BLX r4

        Assert.True(ArmInstructionDecoder.IsThumbRegisterCall(registerBlx));
        Assert.False(ArmInstructionDecoder.IsThumbControlFlowBoundary(registerBlx));
        Assert.True(ArmInstructionDecoder.IsThumbBranchLink(0xF000, 0xC000));
    }

    [Fact]
    public void TryDecodeThumbDirectCall_BlAndBlx_PreserveTargetInstructionSetMode()
    {
        bool decodedBl = ArmInstructionDecoder.TryDecodeThumbDirectCall(
            0xF000,
            0xF800,
            0x1000,
            out ulong blTarget);
        bool decodedBlx = ArmInstructionDecoder.TryDecodeThumbDirectCall(
            0xF000,
            0xE800,
            0x1002,
            out ulong blxTarget);

        Assert.True(decodedBl);
        Assert.Equal(0x1005UL, blTarget);
        Assert.True(decodedBlx);
        Assert.Equal(0x1004UL, blxTarget);
    }

    [Fact]
    public void IsThumbControlFlowBoundary_Movw_IsNotControlFlow()
    {
        const ushort first = 0xF240;
        const ushort second = 0x0001; // MOVW R0, #1

        Assert.Equal(sizeof(uint), ArmInstructionDecoder.GetThumbInstructionSize(first));
        Assert.False(ArmInstructionDecoder.IsThumbControlFlowBoundary(
            first,
            second,
            sizeof(uint)));
    }

    [Fact]
    public void IsArm32ControlFlowBoundary_ConditionalBranch_IsControlFlow()
    {
        const uint branchNotEqual = 0x1A000000u; // BNE +0

        Assert.True(ArmInstructionDecoder.IsArm32ControlFlowBoundary(branchNotEqual));
        Assert.False(ArmInstructionDecoder.IsArm32Return(branchNotEqual));
    }

    [Fact]
    public void IsArm32Return_PopIncludingPc_IsReturn()
    {
        const uint pop = 0xE8BD8010u; // POP {R4,PC}

        Assert.True(ArmInstructionDecoder.IsArm32Return(pop));
        Assert.True(ArmInstructionDecoder.IsArm32ControlFlowBoundary(pop));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void SignExtend_InvalidBitCount_Throws(int bitCount)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ArmInstructionMath.SignExtend(0, bitCount));
    }
}
