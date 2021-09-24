import pwinput
from requests import get
from typing import List
from hashlib import sha1
import time


def get_hashed_passwords(passwords: List[str]) -> List[str]:
    ret = []
    for password in passwords:
        sha1pass = sha1(password.encode('utf-8')).hexdigest().upper()
        ret.append(sha1pass)
    return ret


# we only give the first 5 characters of our sha1 password - k anonymity
def request_matches(head: str) -> List[str]:
    # a nice website for checking this https://haveibeenpwned.com/passwords which also offers the api
    url = 'https://api.pwnedpasswords.com/range/' + '{}'.format(head)
    res = get(url)

    if res.status_code == 200:
        return res.text.splitlines()
    else:
        raise RuntimeError(f'The status code is {res.status_code}')


def check(tail: str, matches: List[str]) -> int:
    ret = 0
    for line in matches:
        pas, count = line.split(':')
        if tail == pas:
           ret = count
    return ret


def respond(count: int, idx: int) -> None:
    print(f'{idx+1}.', end=' ')
    if count == 0:
        print("Your password has not been exposed. Pretty sure you are a hacker!")
    else:
        print(f"Might wanna change your password because it has been leaked {count} times")


if __name__ == '__main__':
    passwords = []
    for idx in range(int(input("How many passwords do you wanna check: "))):
        passwords.append(pwinput.pwinput(prompt="{}. Type your password here: ".format(idx+1), mask='*'))
    start_time = time.time()
    hashs = get_hashed_passwords(passwords)

    for idx, (password, hashed_password) in enumerate(zip(passwords, hashs)):
        head, tail = hashed_password[:5], hashed_password[5:]
        matches = request_matches(head)
        leak_count = check(tail, matches)
        respond(leak_count, idx)
        print(f'\tChecking this password took {time.time()-start_time} s')
    print("You're welcome ;}")