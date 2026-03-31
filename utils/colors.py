from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ==========================
# COLOR FUNCTIONS
# ==========================
def header(msg):
    print(Fore.MAGENTA + Style.BRIGHT + msg)

def info(msg):
    print(Fore.YELLOW + msg)

def success(msg):
    print(Fore.GREEN + msg)

def open_port(msg):
    print(Fore.CYAN + msg)

def warning(msg):
    print(Fore.RED + msg)
    
# ==========================
# MENU OPTION (AUTO PARSE)
# ==========================
def menu_option(text):
    from colorama import Fore, Style

    # split number part and text
    if text.startswith("[") and "]" in text:
        num_part = text.split("]")[0] + "]"
        rest = text[len(num_part):]

        print(
            Fore.CYAN + Style.BRIGHT + num_part +
            Fore.WHITE + rest
        )
    else:
        # fallback (if no number format)
        print(Fore.WHITE + text)
    
def menu_header(msg):
    from colorama import Fore, Style
    print(Fore.MAGENTA + Style.BRIGHT + msg)