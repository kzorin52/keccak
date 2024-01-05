using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Temnij.Security.Cryptography;

public abstract class SHA3Managed : SHA3
{
    private const int KeccakNumberOfRounds = 24;
    private const int KeccakLaneSizeInBits = 8 * 8;

    private static readonly ReadOnlyMemory<ulong> RoundConstants = new(
    [
        0x0000000000000001UL,
        0x0000000000008082UL,
        0x800000000000808aUL,
        0x8000000080008000UL,
        0x000000000000808bUL,
        0x0000000080000001UL,
        0x8000000080008081UL,
        0x8000000000008009UL,
        0x000000000000008aUL,
        0x0000000000000088UL,
        0x0000000080008009UL,
        0x000000008000000aUL,
        0x000000008000808bUL,
        0x800000000000008bUL,
        0x8000000000008089UL,
        0x8000000000008003UL,
        0x8000000000008002UL,
        0x8000000000000080UL,
        0x000000000000800aUL,
        0x800000008000000aUL,
        0x8000000080008081UL,
        0x8000000000008080UL,
        0x0000000080000001UL,
        0x8000000080008008UL
    ]);

    private readonly int _keccakR;
    private Memory<byte> _buffer;
    private int _buffLength;
    private Memory<ulong> _state;

    internal SHA3Managed(int hashBitLength)
    {
        if (hashBitLength != 224 && hashBitLength != 256 && hashBitLength != 384 && hashBitLength != 512)
            throw new ArgumentException("hashBitLength must be 224, 256, 384, or 512", nameof(hashBitLength));

        HashSize = hashBitLength;
        _keccakR = hashBitLength switch
        {
            224 => 1152,
            256 => 1088,
            384 => 832,
            512 => 576,
            _ => _keccakR
        };

        Initialize();
    }

    public override int HashSize { get; }

    protected int SizeInBytes => _keccakR / 8;
    protected int HashByteLength => HashSize / 8;

    public sealed override void Initialize()
    {
        _buffer = new byte[SizeInBytes];
        _buffLength = 0;
        _state = new ulong[5 * 5]; // 1600 bits
    }

    private void AddToBuffer(in ReadOnlySpan<byte> array, ref int offset, ref int count)
    {
        var amount = Math.Min(count, _buffer.Length - _buffLength);
        array[offset..(offset + amount)].CopyTo(_buffer.Span[_buffLength..(_buffLength + amount)]);

        offset += amount;
        _buffLength += amount;
        count -= amount;
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        var source = array.AsSpan();
        base.HashCore(source.Slice(ibStart, cbSize), 0, cbSize);
        if (cbSize == 0)
            return;

        var stride = SizeInBytes / sizeof(ulong);

        if (_buffLength == SizeInBytes)
            throw new Exception("Unexpected error, the internal buffer is full");

        AddToBuffer(source, ref ibStart, ref cbSize);

        Span<ulong> utemps = stackalloc ulong[stride];
        if (_buffLength == SizeInBytes) // buffer full
        {
            AsUlong(_buffer.Span).CopyTo(utemps);
            KeccakF(utemps, stride);
            _buffLength = 0;
        }

        while (cbSize >= SizeInBytes)
        {
            AsUlong(source.Slice(ibStart, SizeInBytes)).CopyTo(utemps);
            KeccakF(utemps, stride);
            ibStart += SizeInBytes;
            cbSize -= SizeInBytes;
        }

        if (cbSize == 0) return; // some left over
        array.AsSpan().Slice(ibStart, cbSize).CopyTo(_buffer.Span[_buffLength..]);
        _buffLength += cbSize;
    }

    protected override byte[] HashFinal()
    {
        _buffer.Span[_buffLength..SizeInBytes].Clear();

        if (UseKeccakPadding)
            _buffer.Span[_buffLength++] = 1; // reference had =, others have ^=
        else
            _buffer.Span[_buffLength++] = 6;
        _buffer.Span[SizeInBytes - 1] |= 0x80;
        var stride = SizeInBytes >> 3;

        var utemps = AsUlong(_buffer.Span);

        KeccakF(utemps, stride);
        return AsBytes(_state.Span, HashByteLength).ToArray();
    }

    private static Span<ulong> AsUlong(in Span<byte> span)
    {
        return MemoryMarshal.Cast<byte, ulong>(span);
    }

    private static Span<byte> AsBytes<T>(in Span<T> span, in int length) where T : unmanaged
    {
        return MemoryMarshal.Cast<T, byte>(span)[..length];
    }

    //[MethodImpl(MethodImplOptions.AggressiveInlining)]
    //private static ulong Rol(in ulong a, in int offset)
    //{
    //    return (a << (offset % KeccakLaneSizeInBits)) ^ (a >> (KeccakLaneSizeInBits - offset % KeccakLaneSizeInBits));
    //}
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Rol(ulong a, int offset)
    {
        offset &= KeccakLaneSizeInBits - 1;
        return (a << offset) | (a >> (KeccakLaneSizeInBits - offset));
    }

    private void KeccakF(Span<ulong> inb, int laneCount)
    {
        var state = _state.Span;
        var roundConstants = RoundConstants.Span;
        while (--laneCount >= 0)
            state[laneCount] ^= inb[laneCount];

        //copyFromState(A, state)
        var aba = state[0];
        var abe = state[1];
        var abi = state[2];
        var abo = state[3];
        var abu = state[4];
        var aga = state[5];
        var age = state[6];
        var agi = state[7];
        var ago = state[8];
        var agu = state[9];
        var aka = state[10];
        var ake = state[11];
        var aki = state[12];
        var ako = state[13];
        var aku = state[14];
        var ama = state[15];
        var ame = state[16];
        var ami = state[17];
        var amo = state[18];
        var amu = state[19];
        var asa = state[20];
        var ase = state[21];
        var asi = state[22];
        var aso = state[23];
        var asu = state[24];

        for (var round = 0; round < KeccakNumberOfRounds; round += 2)
        {
            //    prepareTheta
            var bCa = aba ^ aga ^ aka ^ ama ^ asa;
            var bCe = abe ^ age ^ ake ^ ame ^ ase;
            var bCi = abi ^ agi ^ aki ^ ami ^ asi;
            var bCo = abo ^ ago ^ ako ^ amo ^ aso;
            var bCu = abu ^ agu ^ aku ^ amu ^ asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            var da = bCu ^ Rol(bCe, 1);
            var de = bCa ^ Rol(bCi, 1);
            var di = bCe ^ Rol(bCo, 1);
            var @do = bCi ^ Rol(bCu, 1);
            var du = bCo ^ Rol(bCa, 1);

            aba ^= da;
            bCa = aba;
            age ^= de;
            bCe = Rol(age, 44);
            aki ^= di;
            bCi = Rol(aki, 43);
            amo ^= @do;
            bCo = Rol(amo, 21);
            asu ^= du;
            bCu = Rol(asu, 14);
            var eba = bCa ^ (~bCe & bCi);
            eba ^= roundConstants[round];
            var ebe = bCe ^ (~bCi & bCo);
            var ebi = bCi ^ (~bCo & bCu);
            var ebo = bCo ^ (~bCu & bCa);
            var ebu = bCu ^ (~bCa & bCe);

            abo ^= @do;
            bCa = Rol(abo, 28);
            agu ^= du;
            bCe = Rol(agu, 20);
            aka ^= da;
            bCi = Rol(aka, 3);
            ame ^= de;
            bCo = Rol(ame, 45);
            asi ^= di;
            bCu = Rol(asi, 61);
            var ega = bCa ^ (~bCe & bCi);
            var ege = bCe ^ (~bCi & bCo);
            var egi = bCi ^ (~bCo & bCu);
            var ego = bCo ^ (~bCu & bCa);
            var egu = bCu ^ (~bCa & bCe);

            abe ^= de;
            bCa = Rol(abe, 1);
            agi ^= di;
            bCe = Rol(agi, 6);
            ako ^= @do;
            bCi = Rol(ako, 25);
            amu ^= du;
            bCo = Rol(amu, 8);
            asa ^= da;
            bCu = Rol(asa, 18);
            var eka = bCa ^ (~bCe & bCi);
            var eke = bCe ^ (~bCi & bCo);
            var eki = bCi ^ (~bCo & bCu);
            var eko = bCo ^ (~bCu & bCa);
            var eku = bCu ^ (~bCa & bCe);

            abu ^= du;
            bCa = Rol(abu, 27);
            aga ^= da;
            bCe = Rol(aga, 36);
            ake ^= de;
            bCi = Rol(ake, 10);
            ami ^= di;
            bCo = Rol(ami, 15);
            aso ^= @do;
            bCu = Rol(aso, 56);
            var ema = bCa ^ (~bCe & bCi);
            var eme = bCe ^ (~bCi & bCo);
            var emi = bCi ^ (~bCo & bCu);
            var emo = bCo ^ (~bCu & bCa);
            var emu = bCu ^ (~bCa & bCe);

            abi ^= di;
            bCa = Rol(abi, 62);
            ago ^= @do;
            bCe = Rol(ago, 55);
            aku ^= du;
            bCi = Rol(aku, 39);
            ama ^= da;
            bCo = Rol(ama, 41);
            ase ^= de;
            bCu = Rol(ase, 2);
            var esa = bCa ^ (~bCe & bCi);
            var ese = bCe ^ (~bCi & bCo);
            var esi = bCi ^ (~bCo & bCu);
            var eso = bCo ^ (~bCu & bCa);
            var esu = bCu ^ (~bCa & bCe);

            //    prepareTheta
            bCa = eba ^ ega ^ eka ^ ema ^ esa;
            bCe = ebe ^ ege ^ eke ^ eme ^ ese;
            bCi = ebi ^ egi ^ eki ^ emi ^ esi;
            bCo = ebo ^ ego ^ eko ^ emo ^ eso;
            bCu = ebu ^ egu ^ eku ^ emu ^ esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            da = bCu ^ Rol(bCe, 1);
            de = bCa ^ Rol(bCi, 1);
            di = bCe ^ Rol(bCo, 1);
            @do = bCi ^ Rol(bCu, 1);
            du = bCo ^ Rol(bCa, 1);

            eba ^= da;
            bCa = eba;
            ege ^= de;
            bCe = Rol(ege, 44);
            eki ^= di;
            bCi = Rol(eki, 43);
            emo ^= @do;
            bCo = Rol(emo, 21);
            esu ^= du;
            bCu = Rol(esu, 14);
            aba = bCa ^ (~bCe & bCi);
            aba ^= roundConstants[round + 1];
            abe = bCe ^ (~bCi & bCo);
            abi = bCi ^ (~bCo & bCu);
            abo = bCo ^ (~bCu & bCa);
            abu = bCu ^ (~bCa & bCe);

            ebo ^= @do;
            bCa = Rol(ebo, 28);
            egu ^= du;
            bCe = Rol(egu, 20);
            eka ^= da;
            bCi = Rol(eka, 3);
            eme ^= de;
            bCo = Rol(eme, 45);
            esi ^= di;
            bCu = Rol(esi, 61);
            aga = bCa ^ (~bCe & bCi);
            age = bCe ^ (~bCi & bCo);
            agi = bCi ^ (~bCo & bCu);
            ago = bCo ^ (~bCu & bCa);
            agu = bCu ^ (~bCa & bCe);

            ebe ^= de;
            bCa = Rol(ebe, 1);
            egi ^= di;
            bCe = Rol(egi, 6);
            eko ^= @do;
            bCi = Rol(eko, 25);
            emu ^= du;
            bCo = Rol(emu, 8);
            esa ^= da;
            bCu = Rol(esa, 18);
            aka = bCa ^ (~bCe & bCi);
            ake = bCe ^ (~bCi & bCo);
            aki = bCi ^ (~bCo & bCu);
            ako = bCo ^ (~bCu & bCa);
            aku = bCu ^ (~bCa & bCe);

            ebu ^= du;
            bCa = Rol(ebu, 27);
            ega ^= da;
            bCe = Rol(ega, 36);
            eke ^= de;
            bCi = Rol(eke, 10);
            emi ^= di;
            bCo = Rol(emi, 15);
            eso ^= @do;
            bCu = Rol(eso, 56);
            ama = bCa ^ (~bCe & bCi);
            ame = bCe ^ (~bCi & bCo);
            ami = bCi ^ (~bCo & bCu);
            amo = bCo ^ (~bCu & bCa);
            amu = bCu ^ (~bCa & bCe);

            ebi ^= di;
            bCa = Rol(ebi, 62);
            ego ^= @do;
            bCe = Rol(ego, 55);
            eku ^= du;
            bCi = Rol(eku, 39);
            ema ^= da;
            bCo = Rol(ema, 41);
            ese ^= de;
            bCu = Rol(ese, 2);
            asa = bCa ^ (~bCe & bCi);
            ase = bCe ^ (~bCi & bCo);
            asi = bCi ^ (~bCo & bCu);
            aso = bCo ^ (~bCu & bCa);
            asu = bCu ^ (~bCa & bCe);
        }

        //copyToState(state, A)
        state[0] = aba;
        state[1] = abe;
        state[2] = abi;
        state[3] = abo;
        state[4] = abu;
        state[5] = aga;
        state[6] = age;
        state[7] = agi;
        state[8] = ago;
        state[9] = agu;
        state[10] = aka;
        state[11] = ake;
        state[12] = aki;
        state[13] = ako;
        state[14] = aku;
        state[15] = ama;
        state[16] = ame;
        state[17] = ami;
        state[18] = amo;
        state[19] = amu;
        state[20] = asa;
        state[21] = ase;
        state[22] = asi;
        state[23] = aso;
        state[24] = asu;
    }
}