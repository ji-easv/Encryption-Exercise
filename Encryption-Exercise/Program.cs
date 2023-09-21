using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

string currentPath = Environment.CurrentDirectory;
Console.WriteLine(currentPath);
const ConsoleColor consoleColor = ConsoleColor.DarkMagenta;
const ConsoleColor inputColor = ConsoleColor.White;
const ConsoleColor successColor = ConsoleColor.Green;
const ConsoleColor errorColor = ConsoleColor.DarkRed;

do
{
    Console.ForegroundColor = consoleColor;
    Console.WriteLine("**********************************");
    Console.WriteLine("Welcome to the encryption program!");
    Console.WriteLine("**********************************");
    Console.Write("Enter a passphrase, which will be used to encrypt/decrypt your super secret message: ");
    
    Console.ForegroundColor = inputColor;
    string passphrase = Console.ReadLine();

    Console.ForegroundColor = consoleColor;
    Console.Write("Enter 'E' to encrypt a message or 'D' to decrypt a message. ");
    
    Console.ForegroundColor = errorColor;
    Console.WriteLine("Press 'Q' to quit: ");
   
    Console.ForegroundColor = inputColor;
    var option = Console.ReadKey().Key;
    
    while (option != ConsoleKey.E && option != ConsoleKey.D && option != ConsoleKey.Q)
    {
        Console.ForegroundColor = errorColor;
        Console.WriteLine("Invalid option, please enter 1 or 2 or Q to quit: ");
        Console.ForegroundColor = inputColor;
        option = Console.ReadKey().Key;
    }

    switch (option)
    {
        case ConsoleKey.Q:
            Console.ForegroundColor = consoleColor;
            Console.WriteLine();
            Console.WriteLine("See you next time!");
            return;
        case ConsoleKey.E:
        {
            Console.WriteLine();
            Console.ForegroundColor = consoleColor;
            Console.Write("Enter the message to encrypt: ");
        
            Console.ForegroundColor = inputColor;
            string message = Console.ReadLine();
        
            Console.ForegroundColor = consoleColor;
            Console.Write("Enter the filename to save the encrypted message: ");
        
            Console.ForegroundColor = inputColor;
            string filename = Console.ReadLine();

            // Turn the passphrase into a 256-bit key
            var key = new byte[32];
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 600000, HashAlgorithmName.SHA256);
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
            break;
        }
        default:
        {
            Console.WriteLine();
            Console.ForegroundColor = consoleColor;
            Console.WriteLine("Enter the filename to decrypt: ");
        
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
                using var pbkdf2 = new Rfc2898DeriveBytes(passphrase, salt, 600000, HashAlgorithmName.SHA256);
                key = pbkdf2.GetBytes(32);

                using var aes = new AesGcm(key);
                var plaintextBytes = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

                Console.ForegroundColor = successColor;
                Console.WriteLine("Message decrypted successfully!");
                Console.WriteLine();
            
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

            break;
        }
    }


    Console.WriteLine();
    Console.ForegroundColor = consoleColor;
    Console.Write("Press any key to continue or Q to quit: ");
    Console.WriteLine();
} while (Console.ReadKey().Key != ConsoleKey.Q);

Console.ForegroundColor = consoleColor;
Console.WriteLine();
Console.WriteLine("See you next time!");