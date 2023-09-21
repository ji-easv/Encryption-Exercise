using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

string currentPath = Environment.CurrentDirectory;
Console.WriteLine(currentPath);
ConsoleColor consoleColor = ConsoleColor.DarkMagenta;
ConsoleColor inputColor = ConsoleColor.White;
ConsoleColor successColor = ConsoleColor.Green;
ConsoleColor errorColor = ConsoleColor.DarkRed;

do
{
    Console.ForegroundColor = consoleColor;
    Console.WriteLine("**********************************");
    Console.WriteLine("Welcome to the encryption program!");
    Console.WriteLine("**********************************");
    Console.Write("Enter a passphrase: ");
    
    Console.ForegroundColor = inputColor;
    string passphrase = Console.ReadLine();

    Console.ForegroundColor = consoleColor;
    Console.Write("Enter 1 to encrypt a message or 2 to decrypt a message. ");
    
    Console.ForegroundColor = errorColor;
    Console.Write("Enter Q to quit: ");
   
    Console.ForegroundColor = inputColor;
    string option = Console.ReadLine();
    
    while (option != "1" && option != "2" && option != "Q")
    {
        Console.ForegroundColor = errorColor;
        Console.Write("Invalid option, please enter 1 or 2 or Q to quit: ");
        Console.ForegroundColor = inputColor;
        option = Console.ReadLine();
    }

    if (option == "Q")
    {
        Console.ForegroundColor = consoleColor;
        Console.WriteLine();
        Console.WriteLine("See you next time!");
        return;
    }


    if (int.Parse(option) == 1)
    {
        Console.WriteLine();
        Console.ForegroundColor = consoleColor;
        Console.Write("Enter a message to encrypt: ");
        
        Console.ForegroundColor = inputColor;
        string message = Console.ReadLine();
        
        Console.ForegroundColor = consoleColor;
        Console.Write("Enter a filename to save the encrypted message: ");
        
        Console.ForegroundColor = inputColor;
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
        
        // Write the string array to a new file named "WriteLines.txt".
        using var outputFile = new StreamWriter(Path.Combine(currentPath, $"{filename}.txt"));

        var output = new StringBuilder();
        output.Append(Convert.ToBase64String(nonce));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(ciphertext));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(tag));
        output.Append(" | ");
        output.Append(Convert.ToBase64String(salt));
        
        outputFile.WriteLine(output.ToString());

        Console.ForegroundColor = successColor;
        Console.WriteLine("Message encrypted successfully!");
    }
    else
    {
        Console.ForegroundColor = consoleColor;
        Console.Write("Enter a filename to decrypt: ");
        
        Console.ForegroundColor = ConsoleColor.White;
        string filename = Console.ReadLine();
        try
        {
            // Open the text file using a stream reader.
            using var sr = new StreamReader(Path.Combine(currentPath, $"{filename}.txt"));
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

            Console.ForegroundColor = successColor;
            Console.WriteLine("Message decrypted successfully!");
            
            Console.ForegroundColor = consoleColor;
            Console.WriteLine("Decrypted message: ");
            
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(Encoding.UTF8.GetString(plaintextBytes));
        }
        catch (IOException e)
        {
            Console.ForegroundColor = errorColor;
            Console.WriteLine("The file could not be read.");
            Console.WriteLine(e.Message);
        }
    }
} while (true);
