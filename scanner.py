# scanner.py

import os
import stat
import time
import re
import hashlib
import pefile
from config import KNOWN_MALICIOUS_HASHES, TEXT_FILE_EXTENSIONS, BINARY_FILE_EXTENSIONS
from email_notifier import send_email

def log_result(message):
    """Логирование результатов в файл."""
    with open('logs/scan_log.txt', 'a') as log_file:
        log_file.write(f"{time.ctime()}: {message}\n")

def calculate_hash(file_path):
    """Вычисление хеша SHA-256 файла."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_pe_file(file_path):
    """Анализ PE-файла с помощью библиотеки pefile."""
    try:
        pe = pefile.PE(file_path)
        analysis_result = []
        for section in pe.sections:
            analysis_result.append(f"Section: {section.Name.decode().strip()}, Entropy: {section.get_entropy()}")
        return "\n".join(analysis_result)
    except Exception as e:
        return f"Ошибка при анализе PE-файла: {e}"

def heuristic_analysis(file_path):
    """
    Расширенные эвристические правила для обнаружения подозрительных файлов.
    """
    suspicious = False
    reasons = []

    try:
        # Правило 1: Проверка размера файла
        file_size = os.path.getsize(file_path)
        if file_size > 50 * 1024 * 1024:  # Файлы больше 50 МБ
            suspicious = True
            reasons.append('Большой размер файла')

        # Правило 2: Проверка на скрытые файлы
        if os.path.basename(file_path).startswith('.'):
            suspicious = True
            reasons.append('Скрытый файл')

        # Правило 3: Проверка расширения файла
        extension = os.path.splitext(file_path)[1].lower()
        if extension in BINARY_FILE_EXTENSIONS:
            suspicious = True
            reasons.append('Исполняемый или бинарный файл')

        # Правило 4: Проверка прав доступа к файлу
        mode = os.stat(file_path).st_mode
        if bool(mode & stat.S_IWOTH):  # Файл доступен для записи другими
            suspicious = True
            reasons.append('Файл доступен на запись для всех пользователей')

        # Правило 5: Проверка даты создания/изменения файла
        days = 1  # Файлы, измененные за последние 1 день
        modification_time = os.path.getmtime(file_path)
        if (time.time() - modification_time) < days * 86400:
            suspicious = True
            reasons.append('Файл был изменен в течение последнего дня')

        # Правило 6: Проверка наличия опасных строк в содержимом файлов (только для текстовых файлов)
        if extension in TEXT_FILE_EXTENSIONS:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    dangerous_patterns = ['rm -rf', 'system32', 'powershell', 'wget', 'curl', 'eval', 'exec', 'base64']
                    for pattern in dangerous_patterns:
                        if pattern in content:
                            suspicious = True
                            reasons.append(f"Найден опасный шаблон: {pattern}")
                            break
            except Exception as e:
                reasons.append(f"Не удалось прочитать файл для анализа опасных строк: {e}")

        # Правило 7: Проверка местоположения файла
        system_dirs = ['C:\\Windows', '/usr/bin', '/usr/local/bin']
        for system_dir in system_dirs:
            if file_path.startswith(system_dir) and extension not in BINARY_FILE_EXTENSIONS:
                suspicious = True
                reasons.append('Нестандартный файл в системной директории')

    except Exception as e:
        suspicious = True
        reasons.append(f"Ошибка при анализе файла: {e}")

    return suspicious, ', '.join(reasons)

def extract_strings(file_path):
    """
    Извлекает печатаемые строки из бинарного файла.
    """
    strings = []
    with open(file_path, 'rb') as f:
        data = f.read()
        pattern = re.compile(b'[\x20-\x7E]{4,}')  # Ищем последовательности печатаемых ASCII-символов длиной 4 и более
        for match in pattern.finditer(data):
            strings.append(match.group().decode('ascii', errors='ignore'))
    return '\n'.join(strings)

def scan_file(file_path):
    """
    Сканирует отдельный файл на наличие вирусов.
    """
    print(f"\nАнализ файла: {file_path}")
    log_result(f"Анализ файла: {file_path}")

    # Проверка хеша файла
    file_hash = calculate_hash(file_path)
    if file_hash in KNOWN_MALICIOUS_HASHES:
        print(f"Файл найден в базе известных вредоносных файлов. Хеш: {file_hash}")
        log_result(f"Файл найден в базе известных вредоносных файлов. Хеш: {file_hash}")
        send_email("Обнаружен вредоносный файл", f"Файл {file_path} найден в базе известных вредоносных файлов. Хеш: {file_hash}")
        return

    # Эвристический анализ
    suspicious, reasons = heuristic_analysis(file_path)
    if suspicious:
        print(f"Эвристический анализ: Подозрительный файл. Причина: {reasons}")
        log_result(f"Эвристический анализ: Подозрительный файл. Причина: {reasons}")
        send_email("Обнаружен подозрительный файл", f"Файл {file_path} вызывает подозрения. Причина: {reasons}")
    else:
        print("Эвристический анализ: Файл не вызывает подозрений.")
        log_result("Эвристический анализ: Файл не вызывает подозрений.")

    # Анализ PE-файла
    extension = os.path.splitext(file_path)[1].lower()
    if extension in ['.exe', '.dll', '.sys']:
        pe_analysis_result = analyze_pe_file(file_path)
        print(f"Результат анализа PE-файла: {pe_analysis_result}")
        log_result(f"Результат анализа PE-файла: {pe_analysis_result}")

    # Извлечение строк из бинарного файла
    if extension in BINARY_FILE_EXTENSIONS:
        content = extract_strings(file_path)
        if content.strip():
            print(f"Извлеченные строки из бинарного файла:\n{content}")
            log_result(f"Извлеченные строки из бинарного файла:\n{content}")
        else:
            print("Файл не содержит достаточно текстовой информации для анализа.")
            log_result("Файл не содержит достаточно текстовой информации для анализа.")
