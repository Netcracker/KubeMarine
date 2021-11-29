import unittest

from kubetool import k8s_certs


class K8sCertTest(unittest.TestCase):

    def test_certs_verify_succeeds(self):
        self.assertTrue(k8s_certs.verify_certs_supported(k8s_certs.supported_k8s_certs))

    def test_certs_verify_fails(self):
        with self.assertRaisesRegex(Exception, "Found unsupported cert"):
            k8s_certs.verify_certs_supported(["bad test"])

    def test_single_all_verify_succeeds(self):
        self.assertTrue(k8s_certs.verify_all_is_absent_or_single(["all"]))

    def test_single_all_verify_succeeds_absent(self):
        self.assertTrue(k8s_certs.verify_all_is_absent_or_single(["absent all", "and something else"]))

    def test_single_all_verify_fails(self):
        with self.assertRaisesRegex(Exception, "Found 'all' in certs list, but it is not single"):
            k8s_certs.verify_all_is_absent_or_single(["all", "and something else"])

    def test_correct_cert_list_format(self):
        self.assertTrue(k8s_certs.verify_cert_list_format(["list", "of", "certs"]))

    def test_none_cert_list(self):
        with self.assertRaisesRegex(Exception, "Incorrect k8s certs renew configuration"):
            k8s_certs.verify_cert_list_format(None)

    def test_non_list_cert_list(self):
        with self.assertRaisesRegex(Exception, "Incorrect k8s certs renew configuration"):
            k8s_certs.verify_cert_list_format("value")

    def test_empty_cert_list(self):
        with self.assertRaisesRegex(Exception, "Incorrect k8s certs renew configuration"):
            k8s_certs.verify_cert_list_format([])