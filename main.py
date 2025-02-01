import os
import argparse
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import scan_file, log_result
from config import EMAIL_SETTINGS

def get_user_email():
    """Запрашивает у пользователя email для уведомлений."""
    email = input("Введите ваш email для получения уведомлений: ")
    if email:
        EMAIL_SETTINGS['email_to'] = email
        print(f"Email для уведомлений установлен: {email}")
    else:
        print("Email не был введен. Уведомления отправляться не будут.")

class ChangeHandler(FileSystemEventHandler):
    def __init__(self, scan_file_callback):
        super().__init__()
        self.scan_file_callback = scan_file_callback

    def on_created(self, event):
        if not event.is_directory:
            print(f"\nОбнаружено создание файла: {event.src_path}")
            self.scan_file_callback(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"\nОбнаружено изменение файла: {event.src_path}")
            self.scan_file_callback(event.src_path)

def start_monitoring(directory, scan_file_callback):
    event_handler = ChangeHandler(scan_file_callback)
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)
    observer_thread = threading.Thread(target=observer.start)
    observer_thread.start()
    print(f"Начат мониторинг изменений в директории: {directory}")
    return observer, observer_thread

def main():
    parser = argparse.ArgumentParser(description='Программа для поиска вирусов на ПК с использованием AI.')
    parser.add_argument('directory', help='Директория для сканирования')
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print("Указанная директория не существует.")
        return

    # Запрос email у пользователя
    get_user_email()

    print("Начало сканирования...")
    for root, dirs, files in os.walk(args.directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

    # Запуск мониторинга
    observer, observer_thread = start_monitoring(args.directory, scan_file)

    try:
        # Основной поток ждет завершения мониторинга (который работает бесконечно)
        while observer_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nОстановка мониторинга...")
        observer.stop()
        observer.join()

if __name__ == "__main__":
    main()
