
import requests
import hashlib
import sys

# Request/ Connect to API


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res

# 1. Match first5_char with existent hashes in API
# 2. Gets the list of match hashes
# 3. Loop through previous list to match the tail
# 4. Output count


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Get password
# 1. Hash password using sha1 algorithm
# 2. Save first5_char and tail


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


# Run script if it's the main Script
# Accept as many arguments as you want
# Exit once it runs !

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
