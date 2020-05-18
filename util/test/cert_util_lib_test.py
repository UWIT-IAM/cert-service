import unittest
from certs_util_lib import AddrHelper


class CertUtilLibTest(unittest.TestCase):

    def test_uw_email(self):
        owners = set(['foo', 'bar@baz.com', 'bar'])
        addrs = set(['foo@uw.edu', 'bar@baz.com', 'bar@uw.edu'])
        uw_mail_addrs = set(map(AddrHelper.uwmail, owners))
        self.assertEqual(3, len(addrs.intersection(uw_mail_addrs)))


if __name__ == '__main__':
    unittest.main()
