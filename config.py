
# Настройки для отправки email
EMAIL_SETTINGS = {
    'smtp_server': 'smtp.example.com',  # Замените на ваш SMTP сервер
    'smtp_port': 587,  # Порт SMTP
    'email_from': 'your_email@example.com',  # Ваш email
    'email_password': 'your_email_password',  # Пароль от email
    'email_to': ''  # Получатель уведомлений (оставьте пустым, чтобы пользователь ввел его)
}

# База хеш-сумм известных вредоносных файлов
KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Пример хеша
}

# Расширения файлов
TEXT_FILE_EXTENSIONS = ['.txt', '.py', '.bat', '.cmd', '.js', '.vbs', '.ps1', '.sh',
                        '.html', '.xml', '.json', '.cfg', '.ini', '.php', '.pl', '.rb']

BINARY_FILE_EXTENSIONS = ['.exe', '.dll', '.sys', '.jar', '.class', '.o', '.so',
                          '.pyd', '.scr', '.pif', '.com', '.apk', '.bin']
