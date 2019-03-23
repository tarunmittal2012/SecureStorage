using Android.App;
using Android.OS;
using Android.Print;
using Android.Security;
using Android.Support.V7.App;
using Android.Util;
using Android.Widget;
using Java.Security;
using Javax.Crypto;
using System;
using System.Text;

namespace SecureStorage
{
    [Activity(Label = "@string/app_name", Theme = "@style/AppTheme", MainLauncher = true)]
    public class MainActivity : AppCompatActivity
    {   public  static  string TAG = "SimpleKeystoreApp";
        readonly string transformation = "RSA/ECB/PKCS1Padding";
        EditText encrypt_edit;
        Button encrypt, decrypt;
        TextView encryptText, decryptText;
        PlatformEncryptionKeyHelper _encryptionKeyHelper;
        string stringToEncrypt;
        PrivateKey _privateKey;
        PublicKey _publicKey;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            
            base.OnCreate(savedInstanceState);
            SetContentView(Resource.Layout.activity_main);
            encrypt_edit = FindViewById<EditText>(Resource.Id.encrypt_edit);
            encrypt = FindViewById<Button>(Resource.Id.encrypt_button);
            decrypt = FindViewById<Button>(Resource.Id.decrypt_button);
            encryptText = FindViewById<TextView>(Resource.Id.encrypt_text);
            decryptText = FindViewById<TextView>(Resource.Id.decrypt_text);
            encrypt.Click += Encrypt_Click;
            stringToEncrypt = encrypt_edit.Text.ToString();
            _encryptionKeyHelper = new PlatformEncryptionKeyHelper(Application.Context, "AndroidKeyStore");
            _encryptionKeyHelper.CreateKeyPair();
            _privateKey = _encryptionKeyHelper.GetPrivateKey();
            _publicKey = _encryptionKeyHelper.GetPublicKey();
          }

        private void Encrypt_Click(object sender, EventArgs e)
        {
            Cipher cipher = Cipher.GetInstance(transformation);
            //cipher.Init(CipherMode.EncryptMode, _publicKey);
            var encryptedData = cipher.DoFinal(Encoding.UTF8.GetBytes(stringToEncrypt));
            encryptText.Text = encryptedData.ToString();
        }

     
    }
}