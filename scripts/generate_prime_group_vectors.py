# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Independent integer/affine arithmetic for the retained prime-group vectors."""

import argparse
import hashlib
import json
from pathlib import Path


def add(left, right, p, a):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x = (slope * slope - x1 - x2) % p
    return x, (slope * (x1 - x) - y1) % p


def multiply(n, point, p, a):
    result = None
    while n:
        if n & 1:
            result = add(result, point, p, a)
        point = add(point, point, p, a)
        n >>= 1
    return result


def icart(t, p, a, b):
    # ICAO Doc 9303 Part 11, Appendix B.2, affine equations.
    alpha = -t * t % p
    denominator = a * (alpha + alpha * alpha) % p
    if not denominator:
        raise ValueError('exceptional field element')
    x2 = -b * (1 + alpha + alpha * alpha) * pow(denominator, -1, p) % p
    x3 = alpha * x2 % p
    h2 = (pow(x2, 3, p) + a * x2 + b) % p
    big_a = pow(h2, p - 1 - (p + 1) // 4, p)
    if big_a * big_a * h2 % p == 1:
        result = x2, big_a * h2 % p
    else:
        result = x3, big_a * pow(t, 3, p) * h2 % p
    x, y = result
    if (y * y - x * x * x - a * x - b) % p:
        raise ValueError('invalid point')
    return result


def calculate(domain):
    p, q = (int(domain[key], 16) for key in ('p', 'q'))
    width = (p.bit_length() + 7) // 8
    ec = bool(domain['a'])
    a = int(domain['a'], 16) if ec else 0
    b = int(domain['b'], 16) if ec else 0
    generator_bytes = bytes.fromhex(domain['generator'])
    if ec:
        generator = (int.from_bytes(generator_bytes[1:1 + width], 'big'),
                     int.from_bytes(generator_bytes[1 + width:], 'big'))
        operation = lambda n: multiply(n, generator, p, a)
        encode = lambda point: (b'\x04' + point[0].to_bytes(width, 'big')
                                + point[1].to_bytes(width, 'big')).hex()
    else:
        generator = int.from_bytes(generator_bytes, 'big')
        operation = lambda n: pow(generator, n, p)
        encode = lambda value: value.to_bytes(width, 'big').hex()
    result = {f'multiple_{n}': encode(operation(n)) for n in (2, 3, 6, 11, 22, 33, 66, q - 1)}
    result['negative_generator'] = result.pop(f'multiple_{q - 1}')
    reduction = b''.join(hashlib.sha512(bytes([i])).digest() for i in range(8))
    result['reduction_input'] = reduction.hex()
    result['reduction_expected'] = (int.from_bytes(reduction, 'big') % p).to_bytes(width, 'big').hex()
    result['field_encodings'] = []
    for t in (2, 17, p - 2):
        mapped = icart(t, p, a, b) if ec else pow(t, (p - 1) // q, p)
        if ec:
            if multiply(q, mapped, p, a) is not None:
                raise ValueError('wrong subgroup')
        elif mapped == 1 or pow(mapped, q, p) != 1:
            raise ValueError('wrong subgroup')
        result['field_encodings'].append({'input': t.to_bytes(width, 'big').hex(), 'expected': encode(mapped)})
    # A real nonzero agreement whose canonical encoding starts with zero.
    # This catches accidentally returning minimal-length x coordinates/values.
    point = generator
    for n in range(1, 4097):
        value = point[0] if ec else point
        if value.to_bytes(width, 'big')[0] == 0:
            result['leading_zero_scalar'] = n.to_bytes((q.bit_length() + 7) // 8, 'big').hex()
            result['leading_zero_element'] = encode(point)
            break
        point = add(point, generator, p, a) if ec else point * generator % p
    else:
        raise ValueError('leading zero vector missing')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    document = json.loads(args.path.read_text())
    for row in document['groups']:
        expected = calculate(row['domain'])
        if args.check and row['answers'] != expected:
            raise ValueError('vector mismatch')
        row['answers'] = expected
    if not args.check:
        args.path.write_text(json.dumps(document, indent=2) + '\n')


if __name__ == '__main__':
    main()
