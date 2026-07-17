import requests
import socket
import sys
import time
import json
from test_helper import ApiTestCase
from test_helper import running_process

class TestWhitelist(ApiTestCase):

    def test_NetmaskWhitelist(self):
        r = self.allowFunc('goodie', '193.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.allowFunc('goodie', '2002:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.addBLEntryNetmask("193.168.0.0/16", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addBLEntryNetmask("2002:503:ba3e::/64", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryNetmask("193.168.0.0/16", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryNetmask("2002:503:ba3e::/64", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')
        
        r = self.allowFunc('goodie', '193.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.allowFunc('goodie', '2002:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        time.sleep(11);

        r = self.allowFunc('goodie', '193.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()
        
        r = self.allowFunc('goodie', '2002:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()        
    
    def test_IPWhitelist(self):
        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.allowFunc('goodie', '2001:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

    def test_IPWhitelistDefaultPrefix(self):
        # With wforce6's /24 IPv4 and /64 IPv6 whitelist prefixes, IP-only
        # whitelist entries should override matching blacklist entries within
        # the configured prefix but not outside it.
        r = self.addBLEntryIPPrefixConfig("203.0.113.14", 60, "test prefix blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addBLEntryIPPrefixConfig("203.0.114.14", 60, "test prefix blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryIPPrefixConfig("203.0.113.14", 60, "test prefix whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.allowFuncPrefixConfig('prefixwlip', '203.0.113.99', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        self.assertEqual(j['r_attrs']['whitelisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfig('prefixwlip', '203.0.114.99', "1234")
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        r = self.addBLEntryIPPrefixConfig("2001:db8:2234:5678::1", 60, "test prefix blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addBLEntryIPPrefixConfig("2001:db8:2234:5679::1", 60, "test prefix blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryIPPrefixConfig("2001:db8:2234:5678::1", 60, "test prefix whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.allowFuncPrefixConfig('prefixwlipv6', '2001:db8:2234:5678::abcd', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        self.assertEqual(j['r_attrs']['whitelisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfig('prefixwlipv6', '2001:db8:2234:5679::abcd', "1234")
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        r = self.addBLEntryIP("192.168.72.14", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addBLEntryIP("2001:503:ba3e::2:30", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')
        
        r = self.addWLEntryIP("192.168.72.14", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryIP("2001:503:ba3e::2:30", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.allowFunc('goodie', '2001:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        time.sleep(11);

        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()
        
        r = self.allowFunc('goodie', '2001:503:ba3e::2:30', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()
    
    def test_LoginWhitelist(self):
        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.addBLEntryLogin("goodie", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryLogin("goodie", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')
        
        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        time.sleep(11);

        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

    def test_IPLoginBlacklist(self):
        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        r = self.addBLEntryIPLogin("192.168.72.14", "goodie", 10, "test blacklist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.addWLEntryIPLogin("192.168.72.14", "goodie", 10, "test whitelist")
        j = r.json()
        self.assertEqual(j['status'], 'ok')

        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

    def test_IPLoginWhitelistDefaultPrefix(self):
        # Non-explicit whitelistIPLogin() should use the configured default IP
        # prefix and override only the blacklist entry with the same login.
        attrs = {
            "ip": "203.0.115.14",
            "same_prefix_ip": "203.0.115.99",
            "different_prefix_ip": "203.0.116.14",
            "login": "prefixwl-login",
            "other_login": "prefixwl-other-login"
        }
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPLogin", attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')
        r = self.customFuncPrefixConfigWithName("AddPrefixWhitelistIPLogin", attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        other_attrs = dict(attrs)
        other_attrs["login"] = "prefixwl-other-login"
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPLogin", other_attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        different_prefix_attrs = dict(attrs)
        different_prefix_attrs["ip"] = "203.0.116.14"
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPLogin", different_prefix_attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        r = self.allowFuncPrefixConfig('prefixwl-login', '203.0.115.99', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        self.assertEqual(j['r_attrs']['whitelisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfig('prefixwl-other-login', '203.0.115.99', "1234")
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfig('prefixwl-login', '203.0.116.99', "1234")
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        self.customFuncPrefixConfigWithName("DelPrefixWhitelistIPLogin", attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPLogin", attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPLogin", other_attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPLogin", different_prefix_attrs).close()

    def test_IPJA3WhitelistDefaultPrefix(self):
        # Non-explicit whitelistIPJA3() should use the configured default IP
        # prefix and override only the blacklist entry with the same JA3 value.
        attrs = {
            "ip": "203.0.117.14",
            "same_prefix_ip": "203.0.117.99",
            "different_prefix_ip": "203.0.118.14",
            "ja3": "prefixwl-ja3",
            "other_ja3": "prefixwl-other-ja3"
        }
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPJA3", attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')
        r = self.customFuncPrefixConfigWithName("AddPrefixWhitelistIPJA3", attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        other_attrs = dict(attrs)
        other_attrs["ja3"] = "prefixwl-other-ja3"
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPJA3", other_attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        different_prefix_attrs = dict(attrs)
        different_prefix_attrs["ip"] = "203.0.118.14"
        r = self.customFuncPrefixConfigWithName("AddPrefixBlacklistIPJA3", different_prefix_attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['status'], 'ok')

        r = self.allowFuncPrefixConfigAttrs('prefixwl-ja3-user', '203.0.117.99', "1234", {"ja3":"prefixwl-ja3"})
        j = r.json()
        self.assertEqual(j['status'], 0)
        self.assertEqual(j['r_attrs']['whitelisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfigAttrs('prefixwl-ja3-user', '203.0.117.99', "1234", {"ja3":"prefixwl-other-ja3"})
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        r = self.allowFuncPrefixConfigAttrs('prefixwl-ja3-user', '203.0.118.99', "1234", {"ja3":"prefixwl-ja3"})
        j = r.json()
        self.assertEqual(j['status'], -1)
        self.assertEqual(j['r_attrs']['blacklisted'], '1')
        r.close()

        self.customFuncPrefixConfigWithName("DelPrefixWhitelistIPJA3", attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPJA3", attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPJA3", other_attrs).close()
        self.customFuncPrefixConfigWithName("DelPrefixBlacklistIPJA3", different_prefix_attrs).close()

    def test_ExplicitPrefixWhitelistFunctions(self):
        # Explicit-prefix whitelist Lua functions should honor the supplied
        # prefix even though the main regression instance keeps exact-IP
        # defaults.
        attrs = {
            "ip": "198.51.102.14",
            "same_prefix_ip": "198.51.102.99",
            "different_prefix_ip": "198.51.103.14",
            "login": "explicitwl-login",
            "ja3": "explicitwl-ja3",
            "prefix": "24"
        }
        r = self.customFuncWithName("ExplicitPrefixWhitelist", attrs)
        j = r.json()
        self.assertEqual(j['r_attrs']['login_same_prefix'], 'true')
        self.assertEqual(j['r_attrs']['login_different_prefix'], 'false')
        self.assertEqual(j['r_attrs']['ja3_same_prefix'], 'true')
        self.assertEqual(j['r_attrs']['ja3_different_prefix'], 'false')

        r = self.allowFunc('goodie', '192.168.72.15', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

        time.sleep(11);

        r = self.allowFunc('goodie', '192.168.72.14', "1234")
        j = r.json()
        self.assertEqual(j['status'], 0)
        r.close()

    def test_PersistWhitelist(self):
        cmd3 = ("../wforce/wforce -D -C ./wforce3.conf -R ../wforce/regexes.yaml").split()
        with running_process(cmd3, close_fds=True):
            time.sleep(1)

            r = self.addWLEntryIPPersist("99.99.99.99", 10, "test whitelist")
            j = r.json()
            self.assertEqual(j['status'], 'ok')

        with running_process(cmd3, close_fds=True):
            time.sleep(1)

            r = self.getWLFuncPersist()
            j = r.json()
            self.assertNotEqual(str.find(json.dumps(j),'99.99.99.99'), -1)
