using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;


class Server
{
    private static readonly object consoleLock = new object(); // Лок для синхронізації доступу до консолі
    private static bool isWritingMessage = false; // Флаг, чи сервер пише повідомлення
    private static bool isChatActive = true; // Флаг активності чату

    // Головна програма
    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8; 
        Console.InputEncoding = System.Text.Encoding.UTF8;

        // Кореневий сертифікат додається у довірене сховище
        AddCaCertificateToStore("ca.crt");

        // Шлях до сертифіката сервера та його пароль
        string certPath = "server.pfx";
        string certPassword = "ThebestPassword";
        var serverCertificate = new X509Certificate2(certPath, certPassword); // Завантаження серверного сертифікату

        TcpListener listener = new TcpListener(IPAddress.Any, 5000); // Створення TCP-слухача на порту 5000
        listener.Start();
        Console.WriteLine("Додаток запущено. Очікування підключень клієнту...");

        // Очікування нових підключень клієнтів
        while (true)
        {
            var client = await listener.AcceptTcpClientAsync(); // Підключення від клієнта
            Console.WriteLine("Клієнт підключився!");

            isChatActive = true; 
            _ = HandleClientAsync(client, serverCertificate); // Обробка клієнта в окремому потоці
        }
    }

    // Метод додає кореневий сертифікат CA у сховище
    static void AddCaCertificateToStore(string caCertificatePath)
    {
        try
        {
            var caCertificate = new X509Certificate2(caCertificatePath);

            using (var store = new X509Store(StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(caCertificate);
                store.Close();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Помилка під час додавання сертифіката: {ex.Message}");
        }
    }

    // Метод обробляє підключення клієнта
    static async Task HandleClientAsync(TcpClient client, X509Certificate2 certificate)
    {
        using (var sslStream = new SslStream(client.GetStream(), false, ValidateClientCertificate))
        {
            try
            {
                // SSL-з'єднання з клієнтом
                await sslStream.AuthenticateAsServerAsync(
                   certificate,
                   clientCertificateRequired: true, // Вимагає сертифікат від клієнта
                   enabledSslProtocols: SslProtocols.Tls12, // TLS 1.2
                   checkCertificateRevocation: true); // Перевірка анулювання сертифіката

                Console.WriteLine("З'єднання встановлено.");
                Console.WriteLine("Чат активний. Для заверешення чату закрийте програму або використайте комбінацію Ctrl+C не виділяючи текст");

                var reader = new StreamReader(sslStream);
                var writer = new StreamWriter(sslStream) { AutoFlush = true };

                // Потік для читання повідомлень від клієнта
                _ = Task.Run(async () =>
                {
                    try
                    {
                        string message;
                        while (isChatActive && (message = await reader.ReadLineAsync()) != null)
                        {
                            lock (consoleLock)
                            {
                                ClearCurrentLine();
                                Console.WriteLine($"Клієнт: {message}");
                                if (isWritingMessage)
                                {
                                    Console.Write("Ви: ");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"З'єднання завершено: {ex.Message}");
                    }
                });

                // Цикл для відправлення повідомлень
                while (isChatActive)
                {
                    lock (consoleLock)
                    {
                        isWritingMessage = true; // Позначка, що сервер пише повідомлення
                        Console.Write("Ви: ");
                    }

                    string serverMessage = Console.ReadLine(); // Читання повідомлення з консолі
                    isWritingMessage = false;

                    if (isChatActive && !string.IsNullOrEmpty(serverMessage))
                    {
                        await writer.WriteLineAsync(serverMessage); // Відправка повідомлення клієнту
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка: {ex.Message}");
            }
        }
    }

    // Перевірка сертифікат клієнта
    static bool ValidateClientCertificate(object sender, X509Certificate clientCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        if (clientCertificate == null)
        {
            Console.WriteLine("Помилка. Сертифікат клієнта відсутній.");
            return false;
        }

        // Підготовка кореневого сертифіката до перевірки ланцюга
        X509Chain chain2 = new X509Chain();
        chain2.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Пропуск перевірки на анулювання
        chain2.ChainPolicy.ExtraStore.Add(new X509Certificate2("ca.crt"));

        // Перевірка ланцюга сертифікатів
        if (chain2.Build(new X509Certificate2(clientCertificate)))
        {
            Console.WriteLine("Сертифікат клієнта успішно верифіковано.");
            return true;
        }

        // Помилка
        Console.WriteLine("Помилка. Сертифікат клієнта не підтверджений.");
        foreach (var status in chain2.ChainStatus)
        {
            Console.WriteLine($"Помилка ланцюга сертифікатів: {status.StatusInformation}");
        }

        return false;
    }

    // Очистка поточного рядка (для гарного вигляду)
    static void ClearCurrentLine()
    {
        Console.SetCursorPosition(0, Console.CursorTop);
        Console.Write(new string(' ', Console.WindowWidth));
        Console.SetCursorPosition(0, Console.CursorTop);
    }
}