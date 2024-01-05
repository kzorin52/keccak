using System;
using System.Security.Cryptography;

namespace Temnij.Security.Cryptography
{
    public abstract class SHA3 : HashAlgorithm
    {
        #region Statics
        public new static SHA3 Create()
        {
            return Create("SHA3-256");
        }

        public bool UseKeccakPadding { get; set; }

        public new static SHA3 Create(string hashName)
        {
            return hashName.ToLower().Replace("-", string.Empty) switch
            {
                "sha3224" or "sha3224managed" => new SHA3224Managed(),
                "sha3" or "sha3256" or "sha3256managed" => new SHA3256Managed(),
                "sha3384" or "sha3384managed" => new SHA3384Managed(),
                "sha3512" or "sha3512managed" => new SHA3512Managed(),
                _ => null,
            };
        }
        #endregion

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ArgumentNullException.ThrowIfNull(array);
            ArgumentOutOfRangeException.ThrowIfNegative(ibStart);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(cbSize, array.Length);
            if (ibStart + cbSize > array.Length)
                throw new ArgumentOutOfRangeException(nameof(cbSize));
        }

        protected void HashCore(in ReadOnlySpan<byte> array, int ibStart, int cbSize)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(ibStart);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(cbSize, array.Length);
            if (ibStart + cbSize > array.Length)
                throw new ArgumentOutOfRangeException(nameof(cbSize));
        }
    }
}
