#!/usr/bin/env python

"""
 * CVE-2020-27838
 * CVE-2020-27838 Bug scanner for WebPentesters and Bugbounty Hunters
 *
 * @Developed By Cappricio Securities <https://cappriciosec.com>
 */


"""
import getpass
username = getpass.getuser()


def display_help():
    help_banner = f"""

👋 Hey \033[96m{username}
   \033[92m                                                                          v1.0
   _______    ________    ___   ____ ___   ____       ___  _________ _____ ____
  / ____/ |  / / ____/   |__ \ / __ \__ \ / __ \     |__ \/__  ( __ )__  /( __ )
 / /    | | / / __/________/ // / / /_/ // / / /_______/ /  / / __  |/_ </ __  |
/ /___  | |/ / /__/_____/ __// /_/ / __// /_/ /_____/ __/  / / /_/ /__/ / /_/ /
\____/  |___/_____/    /____/\____/____/\____/     /____/ /_/\____/____/\____/

                              \033[0mDeveloped By \x1b[31;1m\033[4mhttps://cappriciosec.com\033[0m


\x1b[31;1mCVE-2020-27838 : Bug scanner for WebPentesters and Bugbounty Hunters

\x1b[31;1m$ \033[92mCVE-2020-27838\033[0m [option]

Usage: \033[92mCVE-2020-27838\033[0m [options]

Options:
  -u, --url     URL to scan                                CVE-2020-27838 -u https://target.com
  -i, --input   <filename> Read input from txt             CVE-2020-27838 -i target.txt
  -o, --output  <filename> Write output in txt file        CVE-2020-27838 -i target.txt -o output.txt
  -c, --chatid  Creating Telegram Notification             CVE-2020-27838 --chatid yourid
  -b, --blog    To Read about CVE-2020-27838 Bug           CVE-2020-27838 -b
  -h, --help    Help Menu
    """
    print(help_banner)


def banner():
    help_banner = f"""
    \033[94m
👋 Hey \033[96m{username}
      \033[92m                                                                      v1.0
   _______    ________    ___   ____ ___   ____       ___  _________ _____ ____
  / ____/ |  / / ____/   |__ \ / __ \__ \ / __ \     |__ \/__  ( __ )__  /( __ )
 / /    | | / / __/________/ // / / /_/ // / / /_______/ /  / / __  |/_ </ __  |
/ /___  | |/ / /__/_____/ __// /_/ / __// /_/ /_____/ __/  / / /_/ /__/ / /_/ /
\____/  |___/_____/    /____/\____/____/\____/     /____/ /_/\____/____/\____/

                              \033[0mDeveloped By \x1b[31;1m\033[4mhttps://cappriciosec.com\033[0m


\x1b[31;1mCVE-2020-27838 : Bug scanner for WebPentesters and Bugbounty Hunters

\033[0m"""
    print(help_banner)
