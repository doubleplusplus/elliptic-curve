# extended GCD algorithm
def x_gcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

# multiplicative inverse mod n
def mod_inv(a, n):
    g, x, y = x_gcd(a, n)
    if g != 1:
        raise ValueError(f'mod_inv for {a} does not exist')
    return x % n

def get_s(a, p, x1, x2, y1, y2):
    if x1 == x2 and y1 == y2:
        s = ((x1**2 * 3 + a ) * mod_inv(2 * y1, p)) % p
    else:
        de = x2 - x1
        while de < 0:
            de += p
        s = ((y2 - y1) * mod_inv(de, p)) % p
    #print('s =', s)
    return s

def verify(x, y, a, b, p):
    return (y**2 % p) == ((x**3 + a * x + b) % p)

def elli_add(a, p, x1, y1, x2, y2):
    if (-y1) % p == y2 and x1 == x2:  # neutral element
        return 'neutral', 'element'
    else:
        s = get_s(a, p, x1, x2, y1, y2)
        x3 = (s ** 2 - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return x3, y3

def double_and_add(a, p, x, y, n):
    d = bin(n)[3:]  # remove '0b', start from the second bit
    xt, yt = x, y
    for i in d:
        xt, yt = elli_add(a, p, xt, yt, xt, yt)
        if i == '1':
            xt, yt = elli_add(a, p, xt, yt, x, y)
    return xt, yt

# Elliptic Curve Diffie–Hellman Key Exchange
def ecdh():
    p = 1579602854473772853128287506817718026426265023617379175335587248616431
    a = 654624412321892857559038596828572669649402987879847772735693306089759
    b = 563386056159714380473737077729260896240517015706612537779563193095411
    # generator P(x,y)
    x = 953216670857201615849458843136747040308850692140282160349854110301248
    y = 187696769665068572312633292858802066603155820538026405642457554453538
    # Alice private key
    k_prA = 814709178348331822963098404943044035246972495353080501869149056740241
    # Bob private key
    k_prB = 1016189342726403936529228449371555925007815563308599801179551629341341

    # Alice public key, k_pubA = A =  k_prA * P
    A = double_and_add(a, p, x, y, k_prA)
    # Bob public key, k_pubB = B = k_prB * P
    B = double_and_add(a, p, x, y, k_prB)
    print('Alice public key: \n', A)
    print('Bob public key: \n', B)
    # aB = k_prA * B = T
    aB = double_and_add(a, p, B[0], B[1], k_prA)
    print('Alice agreed upon key: \n', aB[0])
    # bA = k_prB * B = T
    bA = double_and_add(a, p, A[0], A[1], k_prB)
    print('Bob agreed upon key: \n', bA[0])

    # agreed upon key using just the private information (A cheating answer)
    cheat = double_and_add(a, p, x, y, k_prA)
    cheat = double_and_add(a, p, cheat[0], cheat[1], k_prB)
    print('cheating answer: \n', cheat[0])

    # add public keys together
    print('adding public keys: \n', (A[0] + B[0], A[1] + B[1]))

ecdh()
