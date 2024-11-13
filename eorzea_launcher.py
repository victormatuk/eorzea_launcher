import keyboard
import signal
import sys
import os
import re
import json
import time
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
import pygetwindow as gw
import pyautogui
import subprocess
import pyotp

#validar OTP durante a inserção
#revisar textos com chat GPT
#Alterar o tema das strings para tema do jogo
#Adicionar tradução para japones
#Adicionar GUI
#Colocar mensagem que pode-se alterar o tempo de cada sleep no arquivo de configuração
#Colocar mensagem que pode-se reiniiar o programa deletando o arquivo de configuração

language = None
data = None

def signal_handler(sig, frame):
    print(colorize(credits(), "BLUE"))
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def focus_window(title_substring):
    windows = gw.getWindowsWithTitle(title_substring)
    if windows:
        window = windows[0]
        pyautogui.press('altleft')
        window.activate()
        return window
    return None

def derive_key(password: str, salt: bytes) -> bytes:
    # Deriva uma chave a partir da senha e do salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))
def encrypt_message(message: str, password: str) -> str:
    # Cria um salt aleatório
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    # Retorna o salt e a mensagem criptografada em base64
    return urlsafe_b64encode(salt + encrypted_message).decode()
def decrypt_message(encrypted_message: str, password: str) -> str:
    # Decodifica o texto criptografado
    encrypted_message = urlsafe_b64decode(encrypted_message)
    salt = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

def select_language():
    while True:
        print("Select your language:")
        print("1: for English")
        print("2: para Português")
        print("3: 日本語（Japanese）")
        choice = input(colorize("[?] Enter the number of your choice: ", "BLUE"))
        if choice == "1":
            return "English"
        elif choice == "2":
            return "Portuguese"
        elif choice == "3":
            return "Japanese"
        else:
            print(colorize("[!] Invalid choice, please try again.", "RED"))
def get_translations():
    return {
        "English": {
            "ask_password": "[?] Enter your game password: ",
            "ask_secret": "[?] Enter your OTP Secret (not the OTP code): ",
            "instructions_enc_password": "[!] You can now create a password to securely protect your game password and OTP code. This password will be required to decrypt them whenever you run this program. If you prefer not to create a password, just press Enter to continue. Your game password and OTP code will still be encrypted, but using a blank password. Keep in mind that without this protection password, anyone using your computer can access the configuration file (which contains your password and OTP code), posing a security risk. We are not responsible for this.",
            "ask_enc_password": "[?] Enter a password to securely store your game password and OTP Secret, or press Enter to proceed without a password: ",
            "ask_dec_password": "[?] Enter the password to decrypt your game password and OTP Secret: ",
            "ok_gogo" : "[OK] Configuration file, {configuration_file_name}, created in the Eorzea Launcher folder. Proceeding...",
            "time_remaining": "Time Remaining: {time}. Press ENTER to skip.",
            "blank_password": "[!] You opted to proceed without a password.",
            "are_you_sure_proceed_with_blank_password": "[?] Are you sure you want to proceed without a password? (Type 'Y' to continue or 'N' to set a password): ",
            "proceed_with_blank_password": "[!] Proceeding with a blank password.",
            "weak_password": "[?] You chose to set a password, but the entered password does not meet the recommended criteria (minimum of 8 characters, including a lowercase letter, an uppercase letter, a number, and a symbol).",
            "starting_script": "[OK] Starting the script",
            "are_you_sure_proceed_with_weak_password": "[?] Are you sure you want to continue with this weak password? (Type 'Y' to proceed or 'N' to enter another password): ",
            "proceed_with_weak_password": "[!] Proceeding with a weak password.",
            "invalid_response_password": "[!] Invalid response. Please type 'Y' to proceed or 'N' to enter another password.",
            "waiting_time_to_load_the_script": "[!] Loading the configuration file... [waiting_time_to_load_the_script]",
            "waiting_time_to_open_the_game": "[!] Waiting for the game to open... [waiting_time_to_open_the_game]",
            "typing_the_password": "[!] Typing the password...",
            "typing_the_otp": "[!] Typing the OTP code...",
            "logging_in": "[!] Clicking the [LOGIN] button...",
            "play": "[!] Waiting for the [PLAY] button to appear to click... [waiting_time_to_load_the_play_button]",
            "waiting_for_the_game_to_open": "[!] Waiting for the game to open... [waiting_time_to_the_game_to_open]",
            "waiting_start_appears": "[!] Waiting for the [START] button to appear... [waiting_time_to_start_appears]",
            "selecting_start": "[!] Selecting [START]...",
            "waiting_char_to_load": "[!] Waiting for the character to load... [waiting_time_to_load_char]",
            "start_the_game": "[!] Choosing the last played character..."
        },
        "Japanese": {
            "ask_password": "[?] ゲームのパスワードを入力してください: ",
            "ask_secret": "[?] OTP Secret を入力してください（OTP コードではありません）: ",
            "instructions_enc_password": "[!] ゲームのパスワードと OTP コードを安全に保護するためのパスワードを作成できます。このパスワードは、プログラムを実行するたびにそれらを復号化するために要求されます。パスワードを作成しない場合は、Enter キーを押して続行してください。ゲームのパスワードと OTP コードは、空のパスワードを使用しても暗号化されます。この保護パスワードがないと、あなたのコンピュータを使用する誰でも設定ファイル（パスワードと OTP コードが含まれています）にアクセスできる可能性があり、セキュリティリスクを伴います。これについては責任を負いません。",
            "ask_enc_password": "[?] ゲームのパスワードと OTP Secret を安全に保存するためのパスワードを入力するか、パスワードなしで続行するには Enter キーを押してください: ",
            "ask_dec_password": "[?] ゲームのパスワードと OTP Secret を復号化するためのパスワードを入力してください: ",
            "ok_gogo" : "[OK] 設定ファイル、{configuration_file_name} が Eorzea Launcher フォルダーに作成されました。続行中...",
            "time_remaining": "残り時間: {time}。スキップするにはENTERを押してください。",
            "blank_password": "[!] パスワードなしで続行することを選択しました。",
            "are_you_sure_proceed_with_blank_password": "[?] パスワードなしで続行してもよろしいですか？（'Y' を入力して続行するか、'N' を入力してパスワードを設定してください）: ",
            "proceed_with_blank_password": "[!] 空のパスワードで続行中。",
            "weak_password": "[?] パスワードを設定することを選択しましたが、入力されたパスワードは推奨される基準を満たしていません（8 文字以上、英小文字、英大文字、数字、記号を含む）。",
            "starting_script": "[OK] スクリプトを開始中",
            "are_you_sure_proceed_with_weak_password": "[?] この弱いパスワードで続行してもよろしいですか？（'Y' を入力して続行するか、'N' を入力して別のパスワードを入力してください）: ",
            "proceed_with_weak_password": "[!] 弱いパスワードで続行中。",
            "invalid_response_password": "[!] 無効な応答です。続行するには 'Y' を入力するか、別のパスワードを入力するには 'N' を入力してください。",
            "waiting_time_to_load_the_script": "[!] 設定ファイルを読み込み中... [waiting_time_to_load_the_script]",
            "waiting_time_to_open_the_game": "[!] ゲームのオープンを待っています... [waiting_time_to_open_the_game]",
            "typing_the_password": "[!] パスワードを入力中...",
            "typing_the_otp": "[!] OTP コードを入力中...",
            "logging_in": "[!] [LOGIN] ボタンをクリック中...",
            "play": "[!] [PLAY] ボタンが表示されるのを待っています... [waiting_time_to_load_the_play_button]",
            "waiting_for_the_game_to_open": "[!] ゲームのオープンを待っています... [waiting_time_to_the_game_to_open]",
            "waiting_start_appears": "[!] [START] ボタンが表示されるのを待っています... [waiting_time_to_start_appears]",
            "selecting_start": "[!] [START] を選択中...",
            "waiting_char_to_load": "[!] キャラクターがロードされるのを待っています... [waiting_time_to_load_char]",
            "start_the_game": "[!] 最後にプレイしたキャラクターを選択中..."
        },
        "Portuguese": {
            "ask_password": "[?] Digite sua senha do jogo: ",
            "ask_secret": "[?] Digite seu OTP Secret (não o código OTP): ",
            "instructions_enc_password": "[!] Agora você pode criar uma senha para proteger sua senha do jogo e seu código OTP de forma segura. Essa senha será solicitada para descriptografá-los sempre que você executar este programa. Se preferir não criar uma senha, apenas pressione Enter para continuar. Sua senha do jogo e o código OTP ainda serão criptografados, mas utilizando uma senha em branco. Tenha em mente que, sem essa senha de proteção, qualquer pessoa que use seu computador poderá acessar o arquivo de configuração (que contém sua senha e o código OTP), o que representa um risco de segurança. Não nos responsabilizamos por isso.",
            "ask_enc_password": "[?] Digite uma senha para armazenar sua senha do jogo e o OTP Secret de forma segura, ou pressione Enter para prosseguir sem senha: ",
            "ask_dec_password": "[?] Digite a senha para descriptografar sua senha do jogo e o OTP Secret: ",
            "ok_gogo" : "[OK] Arquivo de configuração, {configuration_file_name}, criado na pasta do Eorzea Launcher. Prosseguindo...",
            "time_remaining": "Tempo Restante: {time}. Pressione ENTER para pular.",
            "blank_password": "[!] Você optou por prosseguir sem senha.",
            "are_you_sure_proceed_with_blank_password": "[?] Tem certeza de que deseja prosseguir sem senha? (Digite 'S' para continuar ou 'N' para definir uma senha): ",
            "proceed_with_blank_password": "[!] Prosseguindo com senha em branco.",
            "weak_password": "[?] Você escolheu definir uma senha, mas a senha digitada não atende aos critérios recomendados (mínimo de 8 caracteres, contendo uma letra minúscula, uma letra maiúscula, um número e um símbolo).",
            "starting_script": "[OK] Iniciando o script",
            "are_you_sure_proceed_with_weak_password": "[?] Tem certeza de que deseja continuar com essa senha fraca? (Digite 'S' para prosseguir ou 'N' para inserir outra senha): ",
            "proceed_with_weak_password": "[!] Prosseguindo com uma senha fraca.",
            "invalid_response_password": "[!] Resposta inválida. Por favor, digite 'S' para prosseguir ou 'N' para inserir outra senha.",
            "waiting_time_to_load_the_script": "[!] Carregando o arquivo de configuração... [waiting_time_to_load_the_script]",
            "waiting_time_to_open_the_game": "[!] Aguardando o jogo abrir... [waiting_time_to_open_the_game]",
            "typing_the_password": "[!] Digitando a senha...",
            "typing_the_otp": "[!] Digitando o código OTP...",
            "logging_in": "[!] Clicando no botão [LOGIN]...",
            "play": "[!] Aguardando o botão [PLAY] aparecer para clicar... [waiting_time_to_load_the_play_button]",
            "waiting_for_the_game_to_open": "[!] Aguardando o jogo abrir... [waiting_time_to_the_game_to_open]",
            "waiting_start_appears": "[!] Aguardando o botão [START] aparecer... [waiting_time_to_start_appears]",
            "selecting_start": "[!] Selecionando [START]...",
            "waiting_char_to_load": "[!] Aguardando o personagem carregar... [waiting_time_to_load_char]",
            "start_the_game": "[!] Escolhendo o último personagem jogado..."
        }
    }

def display_message(language, message_key, **kwargs):
    translations = get_translations()
    messages = translations.get(language, {})
    message_template = messages.get(message_key, "Message not found.")
    return message_template.format(**kwargs)

def colorize(text, color_code):
    if color_code == "RED":
        color_code = "31"
    elif color_code == "GREEN":
        color_code = "32"
    elif color_code == "YELLOW":
        color_code = "33"
    elif color_code == "BLUE":
        color_code = "34"
    else:
        return text
    return "\033[{}m{}\033[0m".format(color_code, text)
    # print(f"\033[{color_code}m{text}\033[0m")

def check_strength_encryption_password(encryption_password):
    if not encryption_password:
        return False
    if len(encryption_password) < 8:
        return False
    if not re.search(r'[a-z]', encryption_password):
        return False
    if not re.search(r'[A-Z]', encryption_password):
        return False
    if not re.search(r'[0-9]', encryption_password):
        return False
    if not re.search(r'[!@#$%^&*()_+={}\[\]|\\:;"\'<>,.?/]', encryption_password):
        return False
    return True

def openFileConfig(configuration_file_name):
    global data
    can_proceed = False
    data_expected_fields = {"password", "secret", "language"}
    if os.path.exists(configuration_file_name):
        with open(configuration_file_name, 'r') as json_file:
            try:
                data = json.load(json_file)
                missing_fields = data_expected_fields - data.keys() # Verificar se todos os campos estão presentes
                if not missing_fields:
                    can_proceed = True #O arquivo existe e todos os campos estão presentes, tudo OK prosseguir
                else:
                    print(colorize("[!!!!!!!!] The configuration file exists, but the following fields are missing: {}. It will be necessary to reconfigure the Eorzea Launcher.".format(missing_fields), "RED"))
                    can_proceed = False
            except json.JSONDecodeError:
                print(colorize("[!!!!!!!!] The configuration file exists, but there is some error. It will be necessary to reconfigure the Eorzea Launcher.", "RED"))
                can_proceed = False
    return {"can_proceed": can_proceed, "data": data}

def countdown_timer(seconds):
    stop_countdown = False
    def wait_for_enter():
        nonlocal stop_countdown
        try:
            input()
            stop_countdown = True
        except EOFError:
            stop_countdown = True
    enter_thread = threading.Thread(target=wait_for_enter)
    enter_thread.start()
    while seconds and not stop_countdown:
        mins, secs = divmod(seconds, 60)
        timer = f'{mins:02d}:{secs:02d}'
        message = display_message(language, "time_remaining", time=timer)
        len_message = len(message)
        print(f'\r{colorize(message, "WHITE")}', end='')
        time.sleep(1)
        seconds -= 1
    print(f'\r{" " * len_message}', end='\r')

def crystal_of_light():
    crystal = """
             ░          
           ▒▒█ ▒        
         ░▓▒▒█ ░░       
        █▓████  ░       
      █▓███▓▒█▒█░    ░  
    █▒███▓▒█▒ ░  ▒      
    ████▒▒█▒████▒ ░▓ ▓█ 
    ████▒▓▓▒███▒█▒▒▒░▓░ 
    ████▒████▒▓███▒▓░█▒ 
    ████▒█████████▒█  ▒ 
    ████▓▒████████▓█  ▒ 
    ████▒█▓█████████▒▒█ 
    ██████▒█████▒▒█▒▒ ▓ 
    ███████▒▒▒▒▒█▒▓█▒▒█ 
      ███████▓█▒▒█████  
        ██████▒█████░   
          ████▒███░     
           ███▓█▒       
             ░▒

Welcome Warrior of Light to
  [Eorzea Launcher V1.2.1]
"""
    return crystal
def credits():
    credits = """
==================================================
                    Credits
==================================================

Developer:
    - Pixoxo Xoxo, Primal, Famfrit (in-game name)

Special Thanks:
    - (Wife, Tester) Pixoxa Xoxa, Primal, Famfrit (in-game name)

More informations: https://github.com/victormatuk/eorzea_launcher

==================================================
"""
    return credits

def click(target, windows):
    window_width, window_height = windows.width, windows.height
    if target == 'password':
        percent_x = 0.619
        percent_y = 0.463
    elif target == 'otp':
        percent_x = 0.619
        percent_y = 0.542            
    password_field_x = windows.left + window_width * percent_x
    password_field_y = windows.top + window_height * percent_y
    pyautogui.moveTo(password_field_x, password_field_y)
    pyautogui.click()
    #limpar qualquer string
    # pyautogui.press('end')
    # for _ in range(100):
        # pyautogui.press('backspace')

def main():
    global language
    #Welcome screen
    print(colorize(crystal_of_light(), "BLUE"))

    #Checa se tem arquivo de configuração e se o arquivo de configuração tem os parametros necessários
    configuration_file_name = 'eorzea_launcher.config'

    configuration_file = openFileConfig(configuration_file_name)
    can_proceed = configuration_file['can_proceed']
    if not can_proceed: #Re/Configurar o launcher
        language = select_language() #Choose a default language
        password = input(colorize(display_message(language, "ask_password"), "BLUE"))
        secret = input(colorize(display_message(language, "ask_secret"), "BLUE"))
        encryption_password = '';

        encryption_password_created = False
        while not encryption_password_created:
            print(colorize(display_message(language, "instructions_enc_password"), "RED"))
            encryption_password = input(colorize(display_message(language, "ask_enc_password"), "BLUE"))
            if check_strength_encryption_password(encryption_password):
                encryption_password_created = True
            else:
                if encryption_password == '':
                    print(colorize(display_message(language, "blank_password"), "YELLOW"))
                else:
                    print(colorize(display_message(language, "weak_password"), "YELLOW"))
                encryption_password_created = False
                while not encryption_password_created:
                    if encryption_password == '':
                        aceito = input(colorize(display_message(language, "are_you_sure_proceed_with_blank_password"), "BLUE")).strip().lower()
                    else:
                        aceito = input(colorize(display_message(language, "are_you_sure_proceed_with_weak_password"), "BLUE")).strip().lower()
                    if aceito == 's' or aceito == 'y':
                        if encryption_password == '':
                            print(colorize(display_message(language, "proceed_with_blank_password"), "YELLOW"))
                        else:
                            print(colorize(display_message(language, "proceed_with_weak_password"), "YELLOW"))
                        encryption_password_created = True
                    elif aceito == 'n':
                        break
                    else:
                        print(colorize(display_message(language, "invalid_response_password"), "RED"))
        data = {
            "password": encrypt_message(password, encryption_password),
            "secret": encrypt_message(secret, encryption_password),
            "language": language,
            "steam_game_id": "39210",
            "window_title": "FFXIVLauncher",
            "waiting_time_to_load_the_script": 3,
            "waiting_time_to_open_the_game": 25,
            "waiting_time_to_load_the_play_button": 15,
            "waiting_time_to_the_game_to_open": 15,
            "waiting_time_to_start_appears": 20,
            "waiting_time_to_load_char": 20
        }
        with open(configuration_file_name, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(colorize(display_message(language, "ok_gogo", configuration_file_name=configuration_file_name), "GREEN"))
        can_proceed = True
    
    if(can_proceed): #tudo OK, prosseguir
        data = openFileConfig(configuration_file_name)['data'] #Carregar as configurações do arquivo
        language = data['language'] #carrega a linguagem
        print(colorize(display_message(language, "starting_script", configuration_file_name=configuration_file_name), "GREEN"))

        #Descriptografa a senha e o OTP
        passwordOTPOk = False
        encryption_password = '';
        password = ''
        secret = ''
        while not passwordOTPOk:
            try:
                password = decrypt_message(data['password'], encryption_password)
                secret = decrypt_message(data['secret'], encryption_password)
                passwordOTPOk = True
            except Exception as e:
                encryption_password = input(colorize(display_message(language, "ask_dec_password"), "BLUE"))

        # Mensagem de script carregando em X segundos
        print(colorize(display_message(language, "waiting_time_to_load_the_script", waiting_time_to_load_the_script=data['waiting_time_to_load_the_script']), "YELLOW")) #Mensagem
        countdown_timer(data['waiting_time_to_load_the_script']) #Sleep

        #Abre o link da Steam em X segundos se ja nao estiver aberto
        windows = focus_window(data['window_title'])
        if windows is None:
            print(colorize(display_message(language, "waiting_time_to_open_the_game", waiting_time_to_open_the_game=data['waiting_time_to_open_the_game']), "YELLOW"))
            steam_game_id = data['steam_game_id'] #ID do jogo na Steam
            steam_url = f'steam://rungameid/{steam_game_id}'
            subprocess.Popen(['start', steam_url], shell=True)
            countdown_timer(data['waiting_time_to_open_the_game'])

        #Foca na janela
        while True:
            windows = focus_window(data['window_title'])
            if windows is None:
                print(colorize(display_message(language, "waiting_time_to_open_the_game", waiting_time_to_open_the_game=data['waiting_time_to_open_the_game']), "YELLOW"))
                countdown_timer(1)
            else:
                break

        # Digita a senha
        print(colorize(display_message(language, "typing_the_password"), "YELLOW"))
        countdown_timer(1)
        click('password', windows)
        pyautogui.write(password)

        # Aguarda 1 segundo, gera e preenche o OTP
        print(colorize(display_message(language, "typing_the_otp"), "YELLOW"))
        totp = pyotp.TOTP(secret)
        otp = totp.now()
        countdown_timer(1)
        # click('otp', windows)
        pyautogui.press('tab')
        pyautogui.write(otp)
        
        # Aguarda 1 segundo e pula para o botão de autenticação
        countdown_timer(1)
        pyautogui.press('tab')

        # Aguarda 1 segundo e aperta o botão de autenticação
        print(colorize(display_message(language, "logging_in"), "YELLOW"))
        countdown_timer(1)
        pyautogui.press('enter')

        # Aguarda X segundos e aperta o botão play
        print(colorize(display_message(language, "play"), "YELLOW"))
        countdown_timer(data['waiting_time_to_load_the_play_button'])
        pyautogui.press('enter')

        # Aguarda X segundos para o jogo abrir
        print(colorize(display_message(language, "waiting_for_the_game_to_open"), "YELLOW"))
        countdown_timer(data['waiting_time_to_the_game_to_open'])

        # print("Clica na tela do jogo")
        screen_width, screen_height = pyautogui.size()
        center_x = screen_width / 2
        center_y = screen_height / 2
        pyautogui.moveTo(center_x, center_y)
        pyautogui.click()

        # Aguarda X segundos e aperta para baixo
        print(colorize(display_message(language, "waiting_start_appears"), "YELLOW"))
        countdown_timer(data['waiting_time_to_start_appears'])
        
        #Clicando no Start
        print(colorize(display_message(language, "selecting_start"), "YELLOW"))
        pyautogui.press('num0')
        countdown_timer(1)
        pyautogui.press('num0') #Aperta Start
        countdown_timer(1)

        # Aguarda X segundos e aperta enter
        # print("Aperta Start")
        # countdown_timer(1)
        # pyautogui.press('num0')

        # Aguarda X segundo e aperta para baixo para selecionar o char
        print(colorize(display_message(language, "waiting_char_to_load"), "YELLOW"))
        countdown_timer(data['waiting_time_to_load_char'])
        pyautogui.press('num0')

        # Aguarda X segundo e aperta enter para confirmar a selecao do char
        print(colorize(display_message(language, "start_the_game"), "YELLOW"))
        countdown_timer(1)
        pyautogui.press('num0')

        print(colorize(credits(), "BLUE"))
        input(colorize("[!] Press any button to exit", "YELLOW"))
        
if __name__ == "__main__":
    main()