using System;
using System.Text;
using System.Threading.Tasks;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Security;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;


namespace EncryptData
{
    class KeyStoreImpl
    {
        string AES = "AES";
        string CONST_CIPHERTRANSFORMATIONASYMMETRIC = "RSA/ECB/PKCS1Padding";
        string CONST_CIPHERTRANSFORMATIONSYMMETRIC = "AES/GCM/NoPadding";
        string CONST_ANDROIDKEY = "AndroidKeyStore";
        int intializationVector = 12;

        Context appContext;
        string alias;
        KeyStore keyStore;
        private bool HasApiLevel(BuildVersionCodes versionCode) => (int)Build.VERSION.SdkInt >= (int)versionCode;

        public KeyStoreImpl(Context context, string keyStoreAlias)
        {
            appContext = context;
            alias = keyStoreAlias;
            keyStore = KeyStore.GetInstance(CONST_ANDROIDKEY);
            keyStore.Load(null);
        }
        public ISecretKey GetKey()
        {
            if (HasApiLevel(BuildVersionCodes.M))
                return GetSymmetricKey();
            var keyPair = GetAsymmetricKey();
            var keyGenerator = KeyGenerator.GetInstance(AES);
            var defSymmetricKey = keyGenerator.GenerateKey();
            // var newWrappedKey = WrapKey(defSymmetricKey, keyPair.Public);
            return defSymmetricKey;
        }
        //API 23+ Only
        public ISecretKey GetSymmetricKey()
        {
            var existingkey = keyStore.GetKey(alias, null);
            if (existingkey != null)
            {

                var existingSecretKey = existingkey.JavaCast<ISecretKey>();
                return existingSecretKey;
            }
            var keyGenerator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, CONST_ANDROIDKEY);
            var builder = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetBlockModes(KeyProperties.BlockModeGcm)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
                .SetRandomizedEncryptionRequired(false);
            keyGenerator.Init(builder.Build());
            return keyGenerator.GenerateKey();
        }
        //BELOW API 23
        public KeyPair GetAsymmetricKey()
        {
            var asymmetricAlias = $"{alias}.asymmetric";
            var privateKey = keyStore.GetKey(asymmetricAlias, null)?.JavaCast<IPrivateKey>();
            var publicKey = keyStore.GetCertificate(asymmetricAlias)?.PublicKey;
            if (privateKey != null && publicKey != null)
                return new KeyPair(publicKey, privateKey);

            //    var originalLocale = Platform.

            var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa, CONST_ANDROIDKEY);
            var end = DateTime.UtcNow.AddYears(20);
            var startDate = new Java.Util.Date();
            var endDate = new Java.Util.Date(end.Year, end.Month, end.Day);
            var builder = new KeyPairGeneratorSpec.Builder(appContext)
                .SetAlias(asymmetricAlias)
                .SetSerialNumber(Java.Math.BigInteger.One)
                .SetSubject(new Javax.Security.Auth.X500.X500Principal($"CN={asymmetricAlias} CA Certificate"))
                .SetStartDate(startDate)
                .SetEndDate(endDate);

            generator.Initialize(builder.Build());
            return generator.GenerateKeyPair();
        }
        //Encrypting Data
        public byte[] Encrypt(string data)
        {
            var key = GetKey();
            var _iv = new byte[intializationVector];
            var sr = new SecureRandom();
            sr.NextBytes(_iv);
            Cipher cipher;
            try
            {
                cipher = Cipher.GetInstance(CONST_CIPHERTRANSFORMATIONSYMMETRIC);
                cipher.Init(CipherMode.EncryptMode, key, new GCMParameterSpec(128, _iv));
            }
            catch (InvalidAlgorithmParameterException)
            {
                cipher = Cipher.GetInstance(CONST_CIPHERTRANSFORMATIONSYMMETRIC);
                cipher.Init(CipherMode.EncryptMode, key, new IvParameterSpec(_iv));

            }
            var decryptData = Encoding.UTF8.GetBytes(data);
            var encryptByte = cipher.DoFinal(decryptData);
            var r = new byte[_iv.Length + encryptByte.Length];
            Buffer.BlockCopy(_iv, 0, r, 0, _iv.Length);
            Buffer.BlockCopy(encryptByte, 0, r, _iv.Length, encryptByte.Length);

            return r;
        }
        public string Decrypt(byte[] data)
        {
            if (data.Length < intializationVector)
                return null;
            var key = GetKey();
            var _iv = new byte[intializationVector];
            Buffer.BlockCopy(data, 0, _iv, 0, intializationVector);
            Cipher cipher;
            try
            {
                cipher = Cipher.GetInstance(CONST_CIPHERTRANSFORMATIONSYMMETRIC);
                cipher.Init(CipherMode.DecryptMode, key, new GCMParameterSpec(128, _iv));
            }
            catch (InvalidAlgorithmParameterException)
            {
                cipher = Cipher.GetInstance(CONST_CIPHERTRANSFORMATIONSYMMETRIC);
                cipher.Init(CipherMode.DecryptMode, key, new IvParameterSpec(_iv));
            }
            var decryptedData = cipher.DoFinal(data, intializationVector, data.Length - intializationVector);
            return Encoding.UTF8.GetString(decryptedData);
        }
    }
}
