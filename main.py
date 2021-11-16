import json
import os
import secrets
import string
from base64 import b64encode, b64decode
from pathlib import Path
from tkinter import Tk, filedialog

from Crypto.Cipher import AES

# Hlavní třída obsahující logiku aplikace
class ChoiceHandler:
    # Konstruktor
    def __init__(self):
        self.decryptFilename = None
        self.filename = None
        self.decryptMode = None
        self.encryptMode = None
        self.mode = None
        self.parsedMessage = None
        self.keyFromInput = None
        self.iv = None
        self.menu_options_cypher_selection = {
            1: 'Zašifrovat',
            2: 'Dešifrovat',
            3: 'Exit',
        }
        self.menu_options_input_message = {
            1: 'Textový řetězec',
            2: 'Soubor (*.txt)',
            3: 'Exit',
        }
        self.menu_options_key_selection = {
            1: 'Délka 128 b',
            2: 'Délka 192 b',
            3: 'Délka 256 b',
            4: 'Exit',
        }
        self.menu_options_mode_selection = {
            1: 'Mód EAX',
            2: 'Mód CFB',
            3: 'Exit',
        }
        self.menu_options_initialization_vector_selection = {
            1: 'Secure-random',
            2: 'Vlastní',
            3: 'Exit',
        }
        self.menu_options_keep_going = {
            1: 'Ano',
            2: 'Ne (exit)',
        }

    # metoda na výběr typu běhu aplikace - buď zašifrovat nebo dešifrovat.
    # následně volá další metody
    def start(self):
        while self.encryptMode is None or self.decryptMode is None:
            self.print_menu_cypher_selection()
            option = ''
            try:
                option = int(input('Vyberte, jestli chcete šifrovat nebo dešifrovat: '))
            except:
                print('Špatný výběr. Zkuste to znovu.')
            if option == 1:
                self.encryptMode = True
                self.select_input()
                self.select_key()
                self.select_mode()
                self.encryption()
                self.keep_going()
            elif option == 2:
                self.decryptMode = True
                self.select_key()
                self.parse_input_file_for_decryption()
                self.select_mode()
                self.decryption()
                self.keep_going()
            elif option == 3:
                print('Program ukončen.')
                exit()
            else:
                print('Špatný výběr. Vložte číslo mezi 1 až 3.')

    # metoda na výběr, jestli chceme načíst textový soubor nebo zadat text na šifrování ručně
    # pokud uživatel zvolil v předchozím kroku dešifrování, pak vyjede dialog k výběru textového souboru
    def select_input(self):
        if self.encryptMode:
            while self.parsedMessage is None:
                self.print_menu_input_msg()
                option = ''
                try:
                    option = int(input('Vyberte, jestli chcete zašifrovat řetězec, nebo textový soubor: '))
                except:
                    print('Špatný výběr. Zkuste to znovu.')
                if option == 1:
                    self.show_input_text()
                elif option == 2:
                    self.show_input_file_as_text()
                elif option == 3:
                    print('Program ukončen.')
                    exit()
                else:
                    print('Špatný výběr. Vložte číslo mezi 1 až 3.')
        if self.decryptMode:
            self.open_file_text()
            print("Načtěte soubor, který chcete dešifrovat.")

    # metoda, která se uživatele ptá, zda-li chce pokračovat odznovu (volá se úplně na konci po dešifrování nebo šifrování).
    def keep_going(self):
        if self.encryptMode or self.decryptMode:
            while True:
                self.print_menu_keep_going()
                option = ''
                try:
                    option = int(input('Přejete si pokračovat?: '))
                except:
                    print('Špatný výběr. Zkuste to znovu.')
                if option == 1:
                    self.restart_app()
                elif option == 2:
                    exit()
                else:
                    print('Špatný výběr. Vložte číslo mezi 1 až 2.')

    # metoda, která se uživatele ptá, jaký mód chce využít k šifrování - EAX nebo CFB
    def select_mode(self):
        while self.mode is None:
            self.print_menu_mode()
            option = ''
            try:
                option = int(input('Vyberte mód: '))
            except:
                print('Špatný výběr. Zkuste to znovu.')
            if option == 1:
                self.mode = "eax"
            elif option == 2:
                self.mode = "cfb"
                if self.encryptMode is True:
                    self.select_iv()
            elif option == 3:
                print('Program ukončen.')
                exit()
            else:
                print('Špatný výběr. Vložte číslo mezi 1 až 3.')

    # metoda, která se uživatele ptá, jakým způsobem chce vygenerovat IV, buď náhodně nebo může zadat sám.
    def select_iv(self):
        while self.iv is None and self.decryptMode is None:
            self.print_menu_iv_selection()
            option = ''
            try:
                option = int(input('Zvolte způsob generování inicializačního vektoru: '))
            except:
                print('Špatný výběr. Zkuste to znovu.')
            if option == 1:
                self.secure_random_iv()
            elif option == 2:
                self.custom_iv()
            elif option == 3:
                print('Program ukončen.')
                exit()
            else:
                print('Špatný výběr. Vložte číslo mezi 1 až 3.')

    # metoda, která se uživatele ptá, jakou délku klíče chce
    def select_key(self):
        while self.keyFromInput is None:
            self.print_menu_keys()
            option = ''
            try:
                option = int(input('Vyberte délku klíče: '))
            except:
                print('Špatný výběr. Zkuste to znovu.')
            if option == 1:
                self.input_key_128()
            elif option == 2:
                self.input_key_192()
            elif option == 3:
                self.input_key_256()
            elif option == 4:
                print('Program ukončen.')
                exit()
            else:
                print('Špatný výběr. Vložte číslo mezi 1 až 4.')

    # metoda která vytváří dialog k výběru souboru
    def open_file_text(self):
        window = Tk()
        window.wm_attributes('-topmost', 1)
        window.withdraw()
        try:
            self.filename = filedialog.askopenfilename(parent=window,
                                                       initialdir="examples",
                                                       title="Vyberte textový soubor",
                                                       filetypes=(("Text files", "*.txt"), ("All files", "*")))
            return self.filename
        except:
            print("Zvolte soubor!")
            return

    # metoda, která načte do paměti zprávu, kterou zadal uživatel k zašifrování
    def get_input_text_from_user(self):
        input_msg = input("Vložte zprávu k zašifrování: ")
        return input_msg

    # metoda, která parsuje načtený textový soubor (přesněji vezme jeho obsah a zakóduje do bytové podoby)
    def parse_input_file_for_encryption(self):
        while self.filename is None or self.filename == '':
            print("Nevybraný soubor. Vyberte soubor znovu.")
            self.open_file_text()

        if os.path.isfile(self.filename):
            temp = Path(self.filename).read_text()
        else:
            return

        self.parsedMessage = str.encode(temp)

    # metoda, která parsuje zprávu, kterou uživatel zadal (převod na byty)
    def parse_input_text_from_user(self):
        temp = str(self.get_input_text_from_user())
        self.parsedMessage = str.encode(temp)

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_input_msg(self):
        for key in self.menu_options_input_message.keys():
            print(key, '--', self.menu_options_input_message[key])

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_keep_going(self):
        for key in self.menu_options_keep_going.keys():
            print(key, '--', self.menu_options_keep_going[key])

    # ukáže uživateli v konzoli obsah načteného textového souboru, pokud je moc dlouhý, ořeže jej a vypíše kolik znaků ještě zpráva obsahuje
    def show_input_file_as_text(self):
        self.parse_input_file_for_encryption()
        if len(self.parsedMessage) > 100:
            print("Zpráva je příliš dlouhá. Výpis prvních 100 znaků: ")
            print("--------- ZAČÁTEK ZPRÁVY ---------\n")
            print(self.parsedMessage[0:100].decode(), "\n\t ... (", len(self.parsedMessage.decode()) - 100,
                  ") dalších znaků.")
        else:
            print("\nVložená zpráva k zašifrování: \n")
            print("--------- ZAČÁTEK ZPRÁVY ---------\n")
            print(self.parsedMessage.decode())

        print("\n--------- KONEC ZPRÁVY ---------\n")

    # ukáže uživateli v konzoli jeho zprávu k zašifrování, kterou vložil ručně
    def show_input_text(self):
        self.parse_input_text_from_user()
        print("\nVložená zpráva k zašifrování: \n")
        print("--------- ZAČÁTEK ZPRÁVY ---------\n")
        if len(self.parsedMessage) > 100:
            print(self.parsedMessage[0:100].decode(), "\n\t ... (", len(self.parsedMessage.decode()) - 100,
                  ") dalších znaků.")
        else:
            print(self.parsedMessage.decode())
        print("\n--------- KONEC ZPRÁVY ---------\n")

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_keys(self):
        for key in self.menu_options_key_selection.keys():
            print(key, '--', self.menu_options_key_selection[key])

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_mode(self):
        for key in self.menu_options_mode_selection.keys():
            print(key, '--', self.menu_options_mode_selection[key])

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_cypher_selection(self):
        for key in self.menu_options_cypher_selection.keys():
            print(key, '--', self.menu_options_cypher_selection[key])

    # metoda, která vypisuje nabídky pro uživatele (tyto metody se vážou k select_input(), select_mode() atd.)
    def print_menu_iv_selection(self):
        for key in self.menu_options_initialization_vector_selection.keys():
            print(key, '--', self.menu_options_initialization_vector_selection[key])

    # metoda, která požaduje po uživateli správnou délku klíče, dle délky, kterou si vybral v jednom z kroků
    def input_key_128(self):
        key = ""
        while len(key) != 16 or not str.isascii(key):
            key = input("Vložte tajný klíč (16 znaků): ")
            if len(key) != 16:
                print("Vložený počet znaků: ", len(key))
                print("Vložili jste nevhodný počet znaků. Klíč musí mít délku 16 znaků.")
            elif not str.isascii(key):
                print("Vložili jste klíč s diakritikou. Použijte znaky ASCII.")
            else:
                keyasbytearray = str.encode(key)
                self.keyFromInput = keyasbytearray
                return key

    # metoda, která požaduje po uživateli správnou délku klíče, dle délky, kterou si vybral v jednom z kroků
    def input_key_256(self):
        key = ""
        while len(key) != 32 or not str.isascii(key):
            key = input("Vložte tajný klíč (32 znaků): ")
            if len(key) != 32:
                print("Vložený počet znaků: ", len(key))
                print("Vložili jste nevhodný počet znaků. Klíč musí mít délku 32 znaků.")
            elif not str.isascii(key):
                print("Vložili jste klíč s diakritikou. Použijte znaky ASCII.")
            else:
                keyasbytearray = str.encode(key)
                self.keyFromInput = keyasbytearray
                return key

    # metoda, která požaduje po uživateli správnou délku klíče, dle délky, kterou si vybral v jednom z kroků
    def input_key_192(self):
        key = ""
        while len(key) != 24 or not str.isascii(key):
            key = input("Vložte tajný klíč (24 znaků): ")
            if len(key) != 24:
                print("Vložený počet znaků: ", len(key))
                print("Vložili jste nevhodný počet znaků. Klíč musí mít délku 24 znaků.")
            elif not str.isascii(key):
                print("Vložili jste klíč s diakritikou. Použijte znaky ASCII.")
            else:
                keyasbytearray = str.encode(key)
                self.keyFromInput = keyasbytearray
                return key

    # hlavní metoda pro zašifrování, obsahuje rozhodování dle výběru módu a délky klíče uživatele,
    # následně zašifruje zprávu a uloží ji do textového souboru encrypted.txt
    def encryption(self):

        if self.mode == "eax" and len(self.keyFromInput) == 16:
            cipher = AES.new(self.keyFromInput, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(self.parsedMessage)
            file_out = open("encrypted.txt", "wb")
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
            file_out.close()
            print("Zašifrováno pomocí AES128, mód EAX")
            print("Soubor uložen jako encrypted.txt.\n")

        if self.mode == "eax" and len(self.keyFromInput) == 32:
            cipher = AES.new(self.keyFromInput, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(self.parsedMessage)

            file_out = open("encrypted.txt", "wb")
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
            file_out.close()
            print("Zašifrováno pomocí AES256, mód EAX")
            print("Soubor uložen jako encrypted.txt.\n")

        if self.mode == "eax" and len(self.keyFromInput) == 24:
            cipher = AES.new(self.keyFromInput, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(self.parsedMessage)

            file_out = open("encrypted.txt", "wb")
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
            file_out.close()
            print("Zašifrováno pomocí AES192, mód EAX.")
            print("Soubor uložen jako encrypted.txt.\n")

        if self.mode == "cfb" and len(self.keyFromInput) == 16:
            decoded_iv = self.iv.decode()
            cipher = AES.new(self.keyFromInput, AES.MODE_CFB, iv=self.iv)
            ct_bytes = cipher.encrypt(self.parsedMessage)
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv': decoded_iv, 'ciphertext': ct})
            with open("encrypted.txt", "w") as file1:
                file1.write(result)
            print("Zašifrováno pomocí AES128, mód CFB")
            print("Soubor uložen jako encrypted.txt.\n")

        if self.mode == "cfb" and len(self.keyFromInput) == 32:
            decoded_iv = self.iv.decode()
            cipher = AES.new(self.keyFromInput, AES.MODE_CFB, iv=self.iv)
            ct_bytes = cipher.encrypt(self.parsedMessage)
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv': decoded_iv, 'ciphertext': ct})
            with open("encrypted.txt", "w") as file1:
                file1.write(result)
            print("Zašifrováno pomocí AES256, mód CFB")
            print("Soubor uložen jako encrypted.txt.\n")

        if self.mode == "cfb" and len(self.keyFromInput) == 24:
            decoded_iv = self.iv.decode()
            cipher = AES.new(self.keyFromInput, AES.MODE_CFB, iv=self.iv)
            ct_bytes = cipher.encrypt(self.parsedMessage)
            ct = b64encode(ct_bytes).decode('utf-8')
            result = json.dumps({'iv': decoded_iv, 'ciphertext': ct})
            with open("encrypted.txt", "w") as file1:
                file1.write(result)
            print("Zašifrováno pomocí AES128, mód CFB")
            print("Soubor uložen jako encrypted.txt.\n")

    # hlavní metoda pro dešifrování, opět se rozhoduje dle uživatelových předchozích voleb módu/délky klíče
    # taktéž vypisuje dešifrovanou zprávu do konzole a pokud je příliš dlouhá, tak pouze prvních 100 znaků
    def decryption(self):
        try:
            if self.mode == "eax":
                nonce, tag, ciphertext = [self.parsedMessage.read(x) for x in (16, 16, -1)]

                cipher = AES.new(self.keyFromInput, AES.MODE_EAX, nonce)
                data = cipher.decrypt_and_verify(ciphertext, tag)
                if len(data) >= 100:
                    print("Dešifrovaná zpráva je příliš dlouhá. Výpis prvních 100 znaků: ")
                    print("--------- ZAČÁTEK ZPRÁVY ---------\n")
                    print(data[0:100].decode(), "\n\t ... (", len(data.decode()) - 100,
                          ") dalších znaků.")
                else:
                    print("\nDešifrovaný text: \n")
                    print("--------- ZAČÁTEK ZPRÁVY ---------\n")
                    print(data.decode())

                print("\n--------- KONEC ZPRÁVY ---------\n")
                print("\n Dešifrovaný soubor uložen jako: decrypted.txt")
                with open('decrypted.txt', 'w') as f:
                    f.write(data.decode())

        except:
            print("Nelze dešifrovat. Špatně zvolený mód, délka tajného klíče nebo chybný klíč.")

        try:
            if self.mode == "cfb":

                with open(self.filename, 'r') as file:
                    encrypted = file.read()
                b64 = json.loads(encrypted)
                iv = b64['iv']
                encoded_iv = iv.encode()
                ct = b64decode(b64['ciphertext'])
                cipher = AES.new(self.keyFromInput, AES.MODE_CFB, iv=encoded_iv)
                data = cipher.decrypt(ct)
                if len(data) >= 100:
                    print("Dešifrovaná zpráva je příliš dlouhá. Výpis prvních 100 znaků: ")
                    print("--------- ZAČÁTEK ZPRÁVY ---------\n")
                    print(data[0:100].decode(), "\n\t ... (", len(data.decode()) - 100,
                          ") dalších znaků.")
                else:
                    print("\nDešifrovaný text: \n")
                    print("--------- ZAČÁTEK ZPRÁVY ---------\n")
                    print(data.decode())

                print("\n--------- KONEC ZPRÁVY ---------\n")
                print("\n Dešifrovaný soubor uložen jako: decrypted.txt\n")
                with open('decrypted.txt', 'w') as f:
                    f.write(data.decode())

        except:
            print("\nNelze dešifrovat. Špatně zvolený mód, délka tajného klíče nebo chybný klíč.")

    # metoda slouží k parsování souboru k dešifrování (jeho obsah se uloží do třídní proměnné)
    def parse_input_file_for_decryption(self):
        self.open_file_text()
        while self.filename == '':
            print("Nevybraný soubor. Vyberte soubor znovu.")
            self.open_file_text()

        temp = open(self.filename, "rb")
        self.parsedMessage = temp

    # metoda, která generuje náhodný IV (pomocí knihovny secrets, která se používá pro kryptograficky bezpečné generování náhodných čísel)
    # následně string převede do bytů
    def secure_random_iv(self):
        rand = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(16)))
        rand.encode()
        random_as_byte_array = str.encode(rand)
        self.iv = random_as_byte_array

    # metoda, která vezme IV z konzole od uživatele, uloží do proměnné a převede do bytů
    def custom_iv(self):
        temp = ""
        while len(temp) != 16 or not str.isascii(temp):
            temp = input("Vložte inicializační vektor (délka 16 bytů): ")
            if len(temp) != 16:
                print("Vložený počet znaků: ", len(temp))
                print("Vložili jste nevhodný počet znaků. Inicializační vektor musí mít délku 16 znaků")
            elif not str.isascii(temp):
                print("Vložili jste inicializační vektor s diakritikou. Použijte znaky ASCII.")
            else:
                self.iv = temp.encode("utf-8")

    # metoda, která vynuluje globální proměnné - slouží k restartování běhu aplikace po volbě uživatele.
    def restart_app(self):
        self.decryptFilename = None
        self.filename = None
        self.decryptMode = None
        self.encryptMode = None
        self.mode = None
        self.parsedMessage = None
        self.keyFromInput = None
        self.iv = None
        ch.start()

    # main - spouští program


if __name__ == '__main__':
    print("\n##----------------------- INFORMACE O PROGRAMU -----------------------##\n"
          "\nProgram slouží k zašifrování libovolného textu ze vstupu uživatele či z textového souboru s příponou .txt."
          "\nProgram používá šifrovací algoritmus AES. Na výběr jsou 3 délky klíčů - 128 bitů, 192 bitů a 256 bitů."
          "\nK dispozici je volba dvou módů šifrování - EAX a CFB. EAX nevyžaduje zadání inicializačního vektoru."
          "\nU módu CFB lze inicializační vektor zvolit - buď jej zadá uživatel, nebo je vygenerován náhodně."
          "\nDešifrování lze provést tak, že uživatel zná délku skrytého kódu, samotný skrytý kód a mód použitý při "
          "zašifrování. "
          "\nDešifrovat lze pouze textový soubor obsahující zašifrovaný řetězec."
          "\nZašifrovaný text se ukládá do souboru encrypted.txt ve složce s programem."
          "\nDešifrovaný text se ukládá do souboru decrypted.txt ve složce s programem.\n")
    ch = ChoiceHandler()
    ch.start()
