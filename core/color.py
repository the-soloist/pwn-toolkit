#!/usr/bin/env python
from colorama import Fore, Back, Style


def print_color_list():
    # copy from https://gist.github.com/jrjhealey/1eac73a1d1aa411990ab7bfd4a1687d9#file-pythoncolours-py
    print("\033[0;37;40m Normal text        \033[0m     0;37;40m\n")
    print("\033[1;37;40m Bright Colour      \033[0m     1;37;40m\n")
    print("\033[2;37;40m Underlined text    \033[0m     2;37;40m\n")
    print("\033[3;37;40m Negative Colour    \033[0m     3;37;40m\n")
    print("\033[4;37;40m Negative Colour    \033[0m     4;37;40m\n")

    print("\033[1;37;40m \033[2;37:40m TextColour BlackBackground          TextColour GreyBackground                WhiteText ColouredBackground\033[0;37;40m \n \033[0m")
    print("\033[1;30;40m Dark Gray      \033[0m 1;30;40m            \033[0;30;47m Black      \033[0m 0;30;47m               \033[0;37;41m Black      \033[0m 0;37;41m")
    print("\033[1;31;40m Bright Red     \033[0m 1;31;40m            \033[0;31;47m Red        \033[0m 0;31;47m               \033[0;37;42m Black      \033[0m 0;37;42m")
    print("\033[1;32;40m Bright Green   \033[0m 1;32;40m            \033[0;32;47m Green      \033[0m 0;32;47m               \033[0;37;43m Black      \033[0m 0;37;43m")
    print("\033[1;33;40m Yellow         \033[0m 1;33;40m            \033[0;33;47m Brown      \033[0m 0;33;47m               \033[0;37;44m Black      \033[0m 0;37;44m")
    print("\033[1;34;40m Bright Blue    \033[0m 1;34;40m            \033[0;34;47m Blue       \033[0m 0;34;47m               \033[0;37;45m Black      \033[0m 0;37;45m")
    print("\033[1;35;40m Bright Magenta \033[0m 1;35;40m            \033[0;35;47m Magenta    \033[0m 0;35;47m               \033[0;37;46m Black      \033[0m 0;37;46m")
    print("\033[1;36;40m Bright Cyan    \033[0m 1;36;40m            \033[0;36;47m Cyan       \033[0m 0;36;47m               \033[0;37;47m Black      \033[0m 0;37;47m")
    print("\033[1;37;40m White          \033[0m 1;37;40m            \033[0;37;40m Light Grey \033[0m 0;37;40m               \033[0;37;48m Black      \033[0m 0;37;48m")


# Style.DIM is Underlined text
Style.NEGATIVE1 = 3
Style.NEGATIVE2 = 4

# default color conf
yellow = Style.BRIGHT + Fore.YELLOW
white = Style.BRIGHT + Fore.WHITE
green = Style.BRIGHT + Fore.GREEN
blue = Style.BRIGHT + Fore.BLUE
red = Style.BRIGHT + Fore.RED
magenta = Style.BRIGHT + Fore.MAGENTA
cyan = Style.BRIGHT + Fore.CYAN
end = Style.RESET_ALL

# default log conf
prefix_info = Style.BRIGHT + Fore.BLUE
prefix_success = Style.BRIGHT + Fore.GREEN
prefix_warn = Style.BRIGHT + Fore.YELLOW
prefix_error = Style.NORMAL + Fore.WHITE + Back.RED


if __name__ == "__main__":
    print_color_list()
    # redAblack = Style.BRIGHT + Fore.RED + Back.BLACK
    # print(f"{prefix_error}test color{end}")
