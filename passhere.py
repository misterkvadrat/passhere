import json
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# --- СЛОВАРИ ПЕРЕВОДА ---
LANGS = {
    'en': {
        'welcome': "--- PassHere: Secure Password Manager ---",
        'enter_master': "Enter MASTER PASSWORD: ",
        'init_error': "Encryption initialization error.",
        'decrypt_error': "\n[ERROR] Wrong master password or corrupted file!",
        'menu_title': "\nMENU:",
        'menu_show': "1. Show all passwords",
        'menu_add': "2. Add new password",
        'menu_edit': "3. Edit existing password",
        'menu_del': "4. Delete existing password",
        'menu_change': "5. Change Master Password",
        'menu_exit': "6. Exit",
        'choice_prompt': "Choose action (1-6): ",
        'invalid_cmd': "Invalid command.",
        'exit_msg': "Exiting. Vault locked.",
        'vault_empty': "Vault is empty.",
        'acc_list_header': "--- Your Accounts ---",
        'add_title': "\n--- Add New Account ---",
        'prompt_service': "Service name: ",
        'prompt_login': "Login: ",
        'prompt_pass': "Password: ",
        'saved_msg': ">> Account added and saved.",
        'del_title': "\n--- Delete Account ---",
        'del_prompt': "Enter number to DELETE (0 to cancel): ",
        'cancelled': "Cancelled.",
        'deleted_msg': ">> Account '{}' deleted.",
        'edit_title': "\n--- Edit Account ---",
        'edit_prompt': "Enter number to EDIT (0 to cancel): ",
        'edit_keep': "(Press Enter to keep current value)",
        'updated_msg': ">> Changes saved.",
        'invalid_num': "Invalid number.",
        'lang_select': "Select language (en/ru): ",
        # Новые строки для смены пароля
        'change_title': "\n--- Change Master Password ---",
        'enter_old': "Enter OLD master password: ",
        'enter_new': "Enter NEW master password: ",
        'confirm_new': "Confirm NEW master password: ",
        'pass_match_error': "Error: New passwords do not match.",
        'pass_weak_error': "Error: New password is too short (min 4 chars).",
        'change_success': ">> Master password changed successfully! Data re-encrypted.",
        'change_fail': ">> Failed to change password. Old password incorrect?",
        'login_label': "Login"
    },
    'ru': {
        'welcome': "--- PassHere: Безопасный менеджер паролей ---",
        'enter_master': "Введите МАСТЕР-ПАРОЛЬ: ",
        'init_error': "Ошибка инициализации шифрования.",
        'decrypt_error': "\n[ОШИБКА] Неверный мастер-пароль или файл поврежден!",
        'menu_title': "\nМЕНЮ:",
        'menu_show': "1. Показать все пароли",
        'menu_add': "2. Добавить новый пароль",
        'menu_edit': "3. Изменить существующий",
        'menu_del': "4. Удалить существующий",
        'menu_change': "5. Сменить мастер-пароль",
        'menu_exit': "6. Выход",
        'choice_prompt': "Выберите действие (1-6): ",
        'invalid_cmd': "Неверная команда.",
        'exit_msg': "Выход. Хранилище заблокировано.",
        'vault_empty': "Хранилище пусто.",
        'acc_list_header': "--- Ваши аккаунты ---",
        'add_title': "\n--- Добавление нового аккаунта ---",
        'prompt_service': "Название сервиса: ",
        'prompt_login': "Логин: ",
        'prompt_pass': "Пароль: ",
        'saved_msg': ">> Аккаунт добавлен и сохранен.",
        'del_title': "\n--- Удаление аккаунта ---",
        'del_prompt': "Введите номер для УДАЛЕНИЯ (0 для отмены): ",
        'cancelled': "Отмена.",
        'deleted_msg': ">> Аккаунт '{}' удален.",
        'edit_title': "\n--- Редактирование аккаунта ---",
        'edit_prompt': "Введите номер для ИЗМЕНЕНИЯ (0 для отмены): ",
        'edit_keep': "(Нажмите Enter, чтобы оставить текущее значение)",
        'updated_msg': ">> Изменения сохранены.",
        'invalid_num': "Неверный номер.",
        'lang_select': "Выберите язык (en/ru): ",
        # Новые строки для смены пароля
        'change_title': "\n--- Смена мастер-пароля ---",
        'enter_old': "Введите СТАРЫЙ мастер-пароль: ",
        'enter_new': "Введите НОВЫЙ мастер-пароль: ",
        'confirm_new': "Подтвердите НОВЫЙ мастер-пароль: ",
        'pass_match_error': "Ошибка: Новые пароли не совпадают.",
        'pass_weak_error': "Ошибка: Новый пароль слишком короткий (мин. 4 символа).",
        'change_success': ">> Мастер-пароль успешно изменен! Данные перешифрованы.",
        'change_fail': ">> Не удалось сменить пароль. Неверный старый пароль?",
        'login_label': "Логин"
    }
}

# --- КОНФИГУРАЦИЯ ---
DATA_FILE = "vault.enc"
SALT_FILE = "salt.key"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_or_create_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, 'rb') as f:
        return f.read()

def get_fernet_instance(password: str, salt: bytes = None):
    if salt is None:
        salt = load_or_create_salt()
    key = derive_key(password, salt)
    return Fernet(key), salt

def save_vault(vault, fernet):
    data_json = json.dumps(vault, ensure_ascii=False).encode('utf-8')
    encrypted_data = fernet.encrypt(data_json)
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted_data)

def load_vault(fernet, txt):
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        print(txt['decrypt_error'])
        exit(1)

# --- ФУНКЦИИ ИНТЕРФЕЙСА ---

def show_all(vault, txt):
    print(f"\n{txt['acc_list_header']}")
    if not vault:
        print(txt['vault_empty'])
    else:
        for i, acc in enumerate(vault):
            print(f"[{i + 1}] {acc['service']} | {txt['login_label']}: {acc['login']}")
    print("---------------------\n")

def add_new(vault, fernet, txt):
    print(txt['add_title'])
    service = input(txt['prompt_service'])
    login = input(txt['prompt_login'])
    password = input(txt['prompt_pass'])
    vault.append({"service": service, "login": login, "password": password})
    save_vault(vault, fernet)
    print(txt['saved_msg'] + "\n")

def delete_account(vault, fernet, txt):
    show_all(vault, txt)
    if not vault: return
    try:
        choice = input(txt['del_prompt'])
        idx = int(choice) - 1
        if idx == -1:
            print(txt['cancelled'] + "\n")
            return
        if 0 <= idx < len(vault):
            removed = vault.pop(idx)
            save_vault(vault, fernet)
            print(f"{txt['deleted_msg'].format(removed['service'])}\n")
        else:
            print(txt['invalid_num'] + "\n")
    except ValueError:
        print(txt['invalid_num'] + "\n")

def edit_account(vault, fernet, txt):
    show_all(vault, txt)
    if not vault: return
    try:
        choice = input(txt['edit_prompt'])
        idx = int(choice) - 1
        if idx == -1:
            print(txt['cancelled'] + "\n")
            return
        if 0 <= idx < len(vault):
            acc = vault[idx]
            print(f"\nEditing: {acc['service']} ({acc['login']})")
            print(txt['edit_keep'])
            
            new_s = input(f"{txt['prompt_service']}[{acc['service']}]: ")
            new_l = input(f"{txt['prompt_login']}[{acc['login']}]: ")
            new_p = input(f"{txt['prompt_pass']}[{acc['password']}]: ")
            
            if new_s: acc['service'] = new_s
            if new_l: acc['login'] = new_l
            if new_p: acc['password'] = new_p
            
            save_vault(vault, fernet)
            print(txt['updated_msg'] + "\n")
        else:
            print(txt['invalid_num'] + "\n")
    except ValueError:
        print(txt['invalid_num'] + "\n")

def change_master_password(vault, fernet, old_password, txt):
    """
    Логика смены пароля:
    1. Проверяем старый пароль (если мы здесь, значит он уже верный, так как vault загружен).
    2. Запрашиваем новый пароль дважды.
    3. Генерируем новую соль и новый ключ.
    4. Перешифровываем данные новым ключом.
    5. Перезаписываем файл соли и файл данных.
    """
    print(txt['change_title'])
    
    # Для безопасности попросим ввести старый пароль еще раз (опционально, но надежно)
    # Но так как у нас уже есть доступ к vault, мы можем пропустить этот шаг для удобства,
    # либо спросить для подтверждения личности. Давайте спросим для надежности.
    confirm_old = getpass.getpass(txt['enter_old'])
    
    if confirm_old != old_password:
        print(txt['change_fail'])
        return None, None # Возвращаем сигнал неудачи

    new_pass1 = getpass.getpass(txt['enter_new'])
    new_pass2 = getpass.getpass(txt['confirm_new'])

    if new_pass1 != new_pass2:
        print(txt['pass_match_error'])
        return None, None
    
    if len(new_pass1) < 4:
        print(txt['pass_weak_error'])
        return None, None

    # Генерируем новую соль и новый ключ
    new_salt = os.urandom(16)
    new_fernet, _ = get_fernet_instance(new_pass1, new_salt)

    # Перешифровываем данные
    try:
        save_vault(vault, new_fernet)
        
        # Сохраняем новую соль
        with open(SALT_FILE, 'wb') as f:
            f.write(new_salt)
            
        print(txt['change_success'])
        return new_fernet, new_pass1 # Возвращаем новые ключи для продолжения сессии
    except Exception as e:
        print(f"Critical error during re-encryption: {e}")
        print(txt['change_fail'])
        return None, None

# --- ГЛАВНЫЙ ЦИКЛ ---

print("PassHere v1.1 (Multi-language + Change Password)")

# Выбор языка
lang_input = input(LANGS['en']['lang_select'] + " ").lower().strip()
if lang_input.startswith('ru'):
    txt = LANGS['ru']
else:
    txt = LANGS['en']

print(txt['welcome'])

master_password = getpass.getpass(txt['enter_master'])

try:
    fernet, current_salt = get_fernet_instance(master_password)
except Exception:
    print(txt['init_error'])
    exit(1)

vault = load_vault(fernet, txt)

while True:
    print(txt['menu_title'])
    print(txt['menu_show'])
    print(txt['menu_add'])
    print(txt['menu_edit'])
    print(txt['menu_del'])
    print(txt['menu_change'])
    print(txt['menu_exit'])
    
    choice = input(txt['choice_prompt'])
    
    if choice == '1':
        show_all(vault, txt)
    elif choice == '2':
        add_new(vault, fernet, txt)
    elif choice == '3':
        edit_account(vault, fernet, txt)
    elif choice == '4':
        delete_account(vault, fernet, txt)
    elif choice == '5':
        result = change_master_password(vault, fernet, master_password, txt)
        if result[0] is not None:
            # Обновляем активные ключи и пароль в памяти, чтобы можно было работать дальше
            fernet = result[0]
            master_password = result[1]
    elif choice == '6':
        print(txt['exit_msg'])
        break
    else:
        print(txt['invalid_cmd'] + "\n")