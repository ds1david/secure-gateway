"""Bounded future-clock tolerance without expiry or replay grace."""
import datetime
import tempfile
from pathlib import Path
import threading
import unittest
from unittest import mock
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import https_poc as h

NOW = 1800000000
class FixedClock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime.datetime.fromtimestamp(NOW, datetime.timezone.utc)

class MessageClock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public = Path(cls.temp.name) / 'identity.pub'
        cls.public.write_bytes(cls.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def claims(self, issuer='gateway', audience='agent'):
        return dict(iss=issuer, aud=audience, iat=NOW, nbf=NOW, exp=NOW+30,
                    jti='a'*32, scope='POST:/v1/exchange', reply_to='', body={})
    def decode(self, claims):
        token = jwt.encode(claims, self.key, algorithm='RS256')
        with mock.patch('jwt.api_jwt.datetime', FixedClock), mock.patch.object(h.time, 'time', return_value=NOW):
            return h.decode(token, self.public, 'gateway', 'agent')
    def test_accepts_future_iat_and_nbf_through_five_seconds(self):
        for delta in (0, 1, 4, 5):
            with self.subTest(delta=delta):
                claims = self.claims()
                claims.update(iat=NOW+delta, nbf=NOW+delta, exp=NOW+delta+30)
                self.assertEqual(claims, self.decode(claims))
    def test_rejects_future_iat_or_nbf_outside_margin(self):
        for name in ('iat', 'nbf'):
            claims = self.claims()
            claims[name] = NOW+6
            with self.subTest(name=name), self.assertRaises(jwt.ImmatureSignatureError):
                self.decode(claims)
    def test_expiry_has_no_grace_even_at_boundary(self):
        for expiry in (NOW-1, NOW):
            claims = self.claims()
            claims.update(iat=NOW-30, nbf=NOW-30, exp=expiry)
            with self.subTest(expiry=expiry), self.assertRaises(jwt.ExpiredSignatureError):
                self.decode(claims)
    def test_lifetime_and_timestamp_types_remain_bounded(self):
        for changes in ({'exp': NOW+31}, {'iat': True}, {'nbf': str(NOW)}, {'nbf': float(NOW)}):
            claims = self.claims()
            claims.update(changes)
            with self.subTest(changes=changes), self.assertRaises(h.ChannelError):
                self.decode(claims)
    def test_identity_audience_and_required_claims_still_checked(self):
        for changes, error in (({'iss': 'other'}, jwt.InvalidIssuerError),
                               ({'aud': 'other'}, jwt.InvalidAudienceError)):
            claims = self.claims()
            claims.update(changes)
            with self.assertRaises(error):
                self.decode(claims)
        claims = self.claims()
        del claims['nbf']
        with self.assertRaises(jwt.MissingRequiredClaimError):
            self.decode(claims)
    def test_accepted_future_message_cannot_be_replayed(self):
        claims = self.claims()
        claims.update(iat=NOW+5, nbf=NOW+5, exp=NOW+35)
        store = h.ReplayStore(str(Path(self.temp.name) / 'replay.sqlite'))
        try:
            decoded = self.decode(claims)
            with mock.patch.object(h.time, 'time', return_value=NOW):
                store.claim(decoded)
                with self.assertRaises(ValueError):
                    store.claim(decoded)
        finally:
            store.db.close()

class SessionDiagnostics(unittest.TestCase):
    def test_missing_closed_and_wrong_sequence_are_distinct(self):
        state = h.State.__new__(h.State)
        state.config = {}
        state.lock = threading.RLock()
        state.jobs = {}
        body = dict(action='exchange', service='lab-echo', job='fixture', seq=0,
                    data='', closed=False, ready=True)
        with mock.patch.object(h, 'service_allowed', return_value=True):
            with self.assertRaises(h.ChannelError) as error:
                state.exchange(body)
            self.assertEqual('session_not_found', error.exception.reason)
            job = dict(id='fixture', service='lab-echo', assigned=True,
                       done=threading.Event(), seq=1)
            state.jobs['fixture'] = job
            with self.assertRaises(h.ChannelError) as error:
                state.exchange(body)
            self.assertEqual('exchange_sequence_invalid', error.exception.reason)
            job['done'].set()
            with self.assertRaises(h.ChannelError) as error:
                state.exchange(body)
            self.assertEqual('session_closed', error.exception.reason)
