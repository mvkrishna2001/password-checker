import pwinput
from requests import get
from typing import List
from hashlib import sha1
import time


def get_hashed_passwords(passwords: List[str]) -> List[str]:
    return [sha1(password.encode('utf-8')).hexdigest().upper() for password in passwords]


# we only give the first 5 characters of our sha1 password - k anonymity
def request_matches(head: str) -> List[str]:
    # a nice website for checking this https://haveibeenpwned.com/passwords which also offers the api
    return get('https://api.pwnedpasswords.com/range/' + '{}'.format(head)).text.splitlines()


def check(tail: str, matches: List[str]) -> int:
    ret = 0
    for line in matches:
        pas, count = line.split(':')
        if tail == pas:
            ret = count
    return ret


def respond(count: int, idx: int) -> None:
    print(f'{idx+1}.' + {0: "Your password has not been exposed. Pretty sure you are a hacker!", 1: f"Might wanna change your password because it has been leaked {count} times"}[count != 0])


if __name__ == '__main__':
    passwords = [pwinput.pwinput(prompt="{}. Type your password here: ".format(idx+1), mask='*') for idx in range(int(input("How many passwords do you wanna check: ")))]
    start_time = time.time()

    for idx, (password, hashed_password) in enumerate(zip(passwords, get_hashed_passwords(passwords))):
        respond(check(hashed_password[5:], request_matches(hashed_password[:5])), idx)
        print(f'\tChecking this password took {time.time()-start_time} s')
    print("You're welcome ;}")
