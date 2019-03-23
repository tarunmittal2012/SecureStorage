using Android.Content;
using Android.OS;
using Android.Security;
using Android.Security.Keystore;
using Java.Math;
using Java.Security;
using Java.Util;
using Javax.Security.Auth.X500;

namespace SecureStorage
{
    class PlatformEncryptionKeyHelper
    {
        static readonly string KEYSTORE_NAME = "AndroidKeyStore";
        private readonly KeyStore _androidKeyStore;
        private readonly Context _context;
        private readonly string _keyName;
        public int KeySize { get; set; } = 2048;


        public PlatformEncryptionKeyHelper(Context context, string keyName)
       {
           _context = context;
           _keyName = keyName.ToLowerInvariant();
           _androidKeyStore = KeyStore.GetInstance(KEYSTORE_NAME);
           _androidKeyStore.Load(null);
       }
        public void CreateKeyPair()
        {
            DeleteKey();
            KeyPairGenerator keyGenerator =
                KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa, KEYSTORE_NAME);
            if (Build.VERSION.SdkInt >= BuildVersionCodes.JellyBeanMr2 &&
                Build.VERSION.SdkInt <= BuildVersionCodes.LollipopMr1)
            {
                var calendar = Calendar.GetInstance(_context.Resources.Configuration.Locale);
                var endDate = Calendar.GetInstance(_context.Resources.Configuration.Locale);
                endDate.Add(CalendarField.Year, 20);
                //this API is obsolete after Android M, but I am supporting Android L
#pragma warning disable 618
                var builder = new KeyPairGeneratorSpec.Builder(_context)
#pragma warning restore 618
.SetAlias(_keyName).SetSerialNumber(BigInteger.One)
                              .SetSubject(new X500Principal($"CN={_keyName} CA Certificate"))
                              .SetStartDate(calendar.Time)
                              .SetEndDate(endDate.Time).SetKeySize(KeySize);
                keyGenerator.Initialize(builder.Build());
            }
            else if (Build.VERSION.SdkInt >= BuildVersionCodes.M)
            {
                var builder =
                    new KeyGenParameterSpec.Builder(_keyName, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                        .SetBlockModes(KeyProperties.BlockModeEcb)
.SetEncryptionPaddings(KeyProperties.EncryptionPaddingRsaPkcs1)
.SetRandomizedEncryptionRequired(false).SetKeySize(KeySize);
                keyGenerator.Initialize(builder.Build());
            }
            keyGenerator.GenerateKeyPair();
        }
        public IKey GetPublicKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return null;
            return _androidKeyStore.GetCertificate(_keyName)?.PublicKey;
        }
        public IKey GetPrivateKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return null;
            return _androidKeyStore.GetKey(_keyName, null);
        }
        public bool DeleteKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return false;
            _androidKeyStore.DeleteEntry(_keyName);
            return true;
        }
        public bool KeysExist()
        {
            return _androidKeyStore.ContainsAlias(_keyName);
        }
    }

}