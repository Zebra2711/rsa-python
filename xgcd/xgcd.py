from math import gcd,ceil,gcd
from xgcd.xgcd_helper import *
import random

def xgcd_model(a,
               b,
               bit_length=1024,
               constant_time=False,
               min_pair_bezout=False,
               reduction_factor_even=4,
               reduction_factor_odd=4,
               debug_print=False):

    og_debug_print = debug_print

    print_debug(debug_print, f"Initial value a: {a}")
    print_debug(debug_print, f"Initial value b: {b}")
    print_debug(debug_print, f"Reduction factor even: {reduction_factor_even}")
    print_debug(debug_print, f"Reduction factor odd: {reduction_factor_odd}")

    # inputs to XGCD
    start_a, start_b = a, b

    # iterations initialization
    iterations = 0
    # for debugging purposes, keep track of the case transitions
    cases = []

    # remove common factors of 2
    # can skip this if gcd known to be 1
    k = 0
    while (not (a & 1) and not (b & 1)):
        k += 1
        a = a >> 1
        b = b >> 1

    # if one number is even after common factors of 2
    # have been removed, make odd so both inputs to
    # iterations are odd
    even_case = EvenCase.BOTH_ODD
    if not (a & 1):
        a = a + b
        even_case = EvenCase.A_EVEN
    elif not (b & 1):
        b = a + b
        even_case = EvenCase.B_EVEN

    # initialize Bezout coefficient variables
    u, l, y, n = 1, 0, 0, 1
    delta = 0
    # store the odd inputs to iterations (aka a_m, b_m)
    og_a, og_b = a, b

    if constant_time:
        constant_time_iterations = ceil(1.51 * bit_length + 1)

    print_debug(debug_print and even_case != EvenCase.BOTH_ODD, f"Even Case: {even_case}")
    print_debug(debug_print, "Inputs to iterations loop a: ", og_a)
    print_debug(debug_print, "Inputs to iterations loop b: ", og_b)

    sample_break_iterations = 1 if constant_time else 4
    break_condition = True
    while break_condition:
        # for sampling termination condition
        for i in range(sample_break_iterations):

            # print_debug(debug_print, f"a {a} b {b} y {y} n {n} u {u} l {l} delta {delta}")

            iterations += 1

            # a is divisible by 8
            if reduction_factor_even >= 8 and not (a & 7):
                a, u, l = update_a_b_even(cases, 8, a, u, l, og_b, og_a, debug_print, 9)
                delta = delta - 3

            # a is divisible by 4 but not by 8
            elif reduction_factor_even >= 4 and not (a & 3):
                a, u, l = update_a_b_even(cases, 4, a, u, l, og_b, og_a, debug_print, 1)
                delta = delta - 2

            # a is divisible by 2 but not by 4 or 8
            elif not (a & 1):
                a, u, l = update_a_b_even(cases, 2, a, u, l, og_b, og_a, debug_print, 2)
                delta = delta - 1

            # b is divisible by 8
            elif reduction_factor_even >= 8 and not(b & 7):
                b, y, n = update_a_b_even(cases, 8, b, y, n, og_b, og_a, debug_print, 10)
                delta = delta + 3

            # b is divisible by 4 but not by 8
            elif reduction_factor_even >= 4 and not (b & 3):
                b, y, n = update_a_b_even(cases, 4, b, y, n, og_b, og_a, debug_print, 3)
                delta = delta + 2

            # b is divisible by 2 but not by 4 or 8
            elif reduction_factor_even >= 2 and not (b & 1):
                b, y, n = update_a_b_even(cases, 2, b, y, n, og_b, og_a, debug_print, 4)
                delta = delta + 1

            # if a, b are odd, then either a + b or a - b will be divisble by 4

            # a + b is divisible by 4 and delta >= 0 indicates a should be updated
            elif reduction_factor_odd >= 4 and delta >= 0 and not ((b + a) & 3):
                a, u, l = update_a_b_odd(cases, 4, a, b, False, u, l, y, n, og_b, og_a, debug_print, 5)
                delta = delta - 1

                # (a + b) was divisible by 8
                if reduction_factor_odd >= 8 and not (a & 1):
                    a, u, l = update_a_b_even(cases, 2, a, u, l, og_b, og_a, debug_print, 16)
                    delta = delta - 1

            # a - b is divisible by 4 and delta >= 0 indicates a should be updated
            elif reduction_factor_odd >= 4 and delta >= 0:
                a, u, l = update_a_b_odd(cases, 4, a, b, True, u, l, y, n, og_b, og_a, debug_print, 6)
                delta = delta - 1

                # (a - b) was divisible by 8
                if reduction_factor_odd >= 8 and not (a & 1):
                    a, u, l = update_a_b_even(cases, 2, a, u, l, og_b, og_a, debug_print, 18)
                    delta = delta - 1

            # a + b is divisible by 4 and delta < 0 indicates b should be updated
            elif reduction_factor_odd >= 4 and delta < 0 and not ((b + a) & 3):
                b, y, n = update_a_b_odd(cases, 4, a, b, False, u, l, y, n, og_b, og_a, debug_print, 7)
                delta = delta + 1

                # (a + b) was divisible by 8
                if reduction_factor_odd >= 8 and not (b & 1):
                    b, y, n = update_a_b_even(cases, 2, b, y, n, og_b, og_a, debug_print, 20)
                    delta = delta + 1

            # a - b is divisible by 4 and delta < 0 indicates b should be updated
            # if reduction_factor_odd >= 4, this is the last possible case
            elif reduction_factor_odd >= 4 and delta < 0:
                b, y, n = update_a_b_odd(cases, 4, a, b, True, u, l, y, n, og_b, og_a, debug_print, 8)
                delta = delta + 1

                # (a - b) was divisible by 8
                if reduction_factor_odd >= 8 and not (b & 1):
                    b, y, n = update_a_b_even(cases, 2, b, y, n, og_b, og_a, debug_print, 22)
                    delta = delta + 1

            # update with (a - b) / 2 for odd reduction factor of 2
            # update a if delta >= 0
            elif reduction_factor_odd == 2 and delta >= 0:
                a, u, l = update_a_b_odd(cases, 2, a, b, True, u, l, y, n, og_b, og_a, debug_print, 11)
                delta = delta - 1

            # update b if delta < 0
            elif reduction_factor_odd == 2 and delta < 0:
                b, y, n = update_a_b_odd(cases, 2, a, b, True, u, l, y, n, og_b, og_a, debug_print, 12)
                delta = delta + 1

        # constant time breaks after maximum (worst-case) number of iterations
        if constant_time:
            break_condition = (iterations < constant_time_iterations)
            # only print updates during the non-zero iterations for ease of debugging
            debug_print = (a != 0 and b != 0) and og_debug_print
        # non constant time breaks when a or b is 0
        else:
            break_condition = (a != 0 and b != 0)

    debug_print = og_debug_print
    print_debug(debug_print and constant_time, "Note that constant-time debug only prints while variables change.")

    print_debug(debug_print, f"Before post-processing step y: ", y)
    print_debug(debug_print, f"Before post-processing step n: ", n)
    print_debug(debug_print, f"Before post-processing step u: ", u)
    print_debug(debug_print, f"Before post-processing step l: ", l)
    print_debug(debug_print, f"Before post-processing step u + y: ", u + y)
    print_debug(debug_print, f"Before post-processing step u + y: ", l + n)

    if constant_time:
        print_debug(debug_print, f"Constant-time sanity checks: ")
        print_debug(debug_print, f" Cycles: {iterations}")
        print_debug(debug_print, f" Expected: {constant_time_iterations}")
        print_debug(debug_print, f" Bit Length: {bit_length}")

    gcd = a + b
    gcd = gcd * 2**k
    u = u + y
    l = l + n

    if even_case == EvenCase.A_EVEN:
        l = u + l
    elif even_case == EvenCase.B_EVEN:
        u = u + l

    print_debug(debug_print, f"Results: u {u} l {l}")
    print_debug(debug_print, f"a {a} b {b} delta {delta} y {y} n {n} u {u} l {l}")

    assert abs(gcd) == math.gcd(start_a, start_b), f"a: {start_a}, b: {start_b}, expected: {gcd(start_a, start_b)}, computed: {abs(gcd), a, b}"
    assert u * start_a + l * start_b == gcd, f"a: {start_a}, b: {start_b}, u: {u}, l: {l}, gcd: {gcd}, computed: {u * start_a + l * start_b}"

    if min_pair_bezout:
        print_debug(debug_print, "Finding minimum Bezout coefficients...")

        old_u, old_l = u, l
        k = u // (start_b // gcd)

        if k != 0:
            u = u - k * (start_b // gcd)
            l = l + k * (start_a // gcd)

        print_debug(debug_print, f"Min Bezout debug k {k}, u {u}, l {l}, start_b {start_b}, gcd {gcd}, old_u {old_u}, old_l {old_l}")

        # Bezout identity assert
        assert u * start_a + l * start_b == gcd, f"a: {start_a}, b: {start_b}, u: {u}, l: {l}, gcd: {gcd}, computed: {u * start_a + l * start_b}"
        # minimum Bezout coefficients asserts
        assert abs(u) <= abs(start_b / gcd), f"abs u: {abs(u)}, abs start_b / gcd: {abs(start_b / gcd)}"
        assert abs(l) <= abs(start_a / gcd), f"abs l: {abs(l)}, abs start_a / gcd: {abs(start_a / gcd)}"

    if gcd < 0:
        assert -u * start_a + -l * start_b == abs(gcd)
        u = -u
        l = -l

    assert u * start_a + l * start_b == abs(gcd), f"{gcd(start_a, start_b)}"

    print_debug(debug_print, f"Returned results: u {u}")
    print_debug(debug_print, f"Returned results: l {l}")
    print_debug(debug_print, f"Returned results: iterations {iterations}")

    return abs(gcd), u, l, iterations, cases
