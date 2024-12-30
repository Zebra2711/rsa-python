import argparse
def generate_primes(n):
    primes = [2]
    if n == 1:
        return primes
    num = 3
    while len(primes) < n:
        is_prime = True
        for prime in primes:
            if prime * prime > num:
                break
            if num % prime == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
        num += 2
    return primes
parser = argparse.ArgumentParser(description="Generate prime numbers")
parser.add_argument("-n", "--number", type=int, default=3500 ,help="Number of prime numbers to generate")
n = (parser.parse_args()).number
file = open("prime_list.py","w")
file.write(f"list = {generate_primes(n)}")
file.close()
