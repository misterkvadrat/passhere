import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import getpass

print("--- PassHere v0.6: Управление (Add/Edit/Delete) ---")

DATA_FILE = "vault.enc"
SALT_FILE = "salt.key"

# --- Криптография (без изменений) ---

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_or_create_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        return salt
    else:
        with open(SALT_FILE, 'rb') as f:
            return f.read()

def get_fernet_instance(password: str):
    salt = load_or_create_salt()
    key = derive_key(password, salt)
    return Fernet(key)

def save_vault(vault, fernet):
    data_json = json.dumps(vault, ensure_ascii=False).encode('utf-8')
    encrypted_data = fernet.encrypt(data_json)
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted_data)
    # print(">> Данные сохранены.") # Скрыли сообщение для чистоты вывода

def load_vault(fernet):
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        vault = json.loads(decrypted_data.decode('utf-8'))
        return vault
    except Exception:
        print("\n[ОШИБКА] Неверный мастер-пароль или файл поврежден!")
        exit(1)

# --- Функции интерфейса ---

def show_all(vault):
    print("\n--- Ваши аккаунты ---")
    if not vault:
        print("Хранилище пусто.")
    else:
        for i, acc in enumerate(vault):
            print(f"[{i + 1}] {acc['service']} | Логин: {acc['login']}")
            # Пароль скрыт в списке для безопасности
    print("---------------------\n")

def add_new(vault, fernet):
    print("\n--- Добавление нового аккаунта ---")
    service = input("Название сервиса: ")
    login = input("Логин: ")
    password = input("Пароль: ")
    
    vault.append({"service": service, "login": login, "password": password})
    save_vault(vault, fernet)
    print(">> Аккаунт добавлен и сохранен.\n")

def delete_account(vault, fernet):
    show_all(vault)
    if not vault:
        return

    try:
        choice = input("Введите номер аккаунта для УДАЛЕНИЯ (или 0 для отмены): ")
        idx = int(choice) - 1
        
        if idx == -1:
            print("Отмена.\n")
            return
            
        if 0 <= idx < len(vault):
            removed = vault.pop(idx)
            save_vault(vault, fernet)
            print(f">> Аккаунт '{removed['service']}' удален.\n")
        else:
            print("Неверный номер.\n")
    except ValueError:
        print("Нужно ввести число!\n")

def edit_account(vault, fernet):
    show_all(vault)
    if not vault:
        return

    try:
        choice = input("Введите номер аккаунта для ИЗМЕНЕНИЯ (или 0 для отмены): ")
        idx = int(choice) - 1
        
        if idx == -1:
            print("Отмена.\n")
            return

        if 0 <= idx < len(vault):
            acc = vault[idx]
            print(f"\nРедактирование: {acc['service']} ({acc['login']})")
            print("(Нажмите Enter, чтобы оставить текущее значение)")
            
            new_service = input(f"Сервис [{acc['service']}]: ")
            new_login = input(f"Логин [{acc['login']}]: ")
            new_password = input(f"Пароль [{acc['password']}]: ")
            
            # Обновляем только если введено новое значение
            if new_service: acc['service'] = new_service
            if new_login: acc['login'] = new_login
            if new_password: acc['password'] = new_password
            
            save_vault(vault, fernet)
            print(">> Изменения сохранены.\n")
        else:
            print("Неверный номер.\n")
    except ValueError:
        print("Нужно ввести число!\n")

# --- ГЛАВНЫЙ ЦИКЛ ---

# 1. Вход
# getpass.getpass() не выводит ввод на экран
master_password = getpass.getpass("Введите МАСТЕР-ПАРОЛЬ: ")
try:
    fernet = get_fernet_instance(master_password)
except Exception:
    print("Ошибка инициализации шифрования.")
    exit(1)

vault = load_vault(fernet)

while True:
    print("МЕНЮ:")
    print("1. Показать список")
    print("2. Добавить новый")
    print("3. Изменить существующий")
    print("4. Удалить существующий")
    print("5. Выход")
    
    choice = input("Выбор (1-5): ")
    
    if choice == '1':
        show_all(vault)
    elif choice == '2':
        add_new(vault, fernet)
    elif choice == '3':
        edit_account(vault, fernet)
    elif choice == '4':
        delete_account(vault, fernet)
    elif choice == '5':
        print("Выход. Хранилище заблокировано.")
        break
    else:
        print("Неверная команда.\n")