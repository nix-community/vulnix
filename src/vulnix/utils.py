def cve_url(cve_id):
    return ('https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'.
            format(cve_id))


def batch(iterable, size, callable):
    b = size
    for x in iterable:
        yield x
        b -= 1
        if not b:
            callable()
            b = size
