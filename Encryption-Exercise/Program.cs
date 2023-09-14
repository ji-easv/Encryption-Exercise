using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

string docPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

Console.WriteLine("Welcome to the encryption program!");
Console.Write("Enter a passphrase: ");
string passphrase = Console.ReadLine();

while (true)
{
    Console.Write("Enter 1 to encrypt a message or 2 to decrypt a message. Press Q to quit: ");
    string option = Console.ReadLine();

    while (option != "1" && option != "2" && option != "Q")
    {
        Console.Write("Invalid option, please enter 1 or 2 or Q to quit: ");
        option = Console.ReadLine();
    }

    if (option == "Q")
    {
        Console.WriteLine("Goodbye!");
        return;
    }


    if (int.Parse(option) == 1)
    {
        Console.Write("Enter a message to encrypt: ");
        string message = Console.ReadLine();
        Console.Write("Enter a filename to save the encrypted message: ");
        string filename = Console.ReadLine();
        
        // Turn the passphrase into a 256-bit key
        var key = new byte[32];
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000, HashAlgorithmName.SHA256);
        key = pbkdf2.GetBytes(32);

        using var aes = new AesGcm(key);
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);

        var plaintextBytes = Encoding.UTF8.GetBytes(message);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
       

        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Set a variable to the Documents path.

        // Write the string array to a new file named "WriteLines.txt".
        using var outputFile = new StreamWriter(Path.Combine(docPath, $"{filename}.txt"));

        var output = new StringBuilder();
        output.Append(Convert.ToBase64String(nonce));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(ciphertext));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(tag));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(salt));

        outputFile.WriteLine(output.ToString());

        Console.WriteLine("Message encrypted successfully!");
    }
    else
    {
        Console.Write("Enter a filename to decrypt: ");
        string filename = Console.ReadLine();
        try
        {
            // Open the text file using a stream reader.
            using var sr = new StreamReader(Path.Combine(docPath, filename));
            var fileContent = sr.ReadToEnd();
            var fileContentArray = fileContent.Split(" | ");
            var nonce = Convert.FromBase64String(fileContentArray[0]);
            var ciphertext = Convert.FromBase64String(fileContentArray[1]);
            var tag = Convert.FromBase64String(fileContentArray[2]);
            var salt = Convert.FromBase64String(fileContentArray[3]);
            var key = new byte[32];

            // Turn the passphrase into a 256-bit key to decrypt
            using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 10000, HashAlgorithmName.SHA256);
            key = pbkdf2.GetBytes(32);

            using var aes = new AesGcm(key);
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            Console.WriteLine("Message decrypted successfully!");
            Console.WriteLine(Encoding.UTF8.GetString(plaintextBytes));
        }
        catch (IOException e)
        {
            Console.WriteLine("The file could not be read.");
            Console.WriteLine(e.Message);
        }
    }
}