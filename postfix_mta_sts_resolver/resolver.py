import asyncio
import enum
import logging
from io import BytesIO

import aiodns
import aiodns.error
import aiohttp

from . import defaults
from .utils import parse_mta_sts_record, parse_mta_sts_policy, is_plaintext, filter_text
from .constants import HARD_RESP_LIMIT, CHUNK


class BadSTSPolicy(Exception):
    pass


class STSFetchResult(enum.Enum):
    NONE = 0
    VALID = 1
    FETCH_ERROR = 2
    NOT_CHANGED = 3


_HEADERS = {"User-Agent": defaults.USER_AGENT}


def _extract_txt_records(dns_result):
    """Normalize a DNS TXT query result to a list of record text values.

    aiodns >= 4.0 ``query_dns()`` returns a ``DNSResult`` whose ``.answer``
    is a list of ``DNSRecord`` objects. The answer can contain non-TXT
    records (e.g. a CNAME when the STS host is an alias for another name),
    so select only TXT records; each TXT record's ``.data`` is a
    ``TXTRecordData`` holding the raw TXT bytes in ``.data``. aiodns 3.x
    ``query()`` returns a list of records exposing the text directly via
    ``.text``.
    """
    if hasattr(dns_result, 'answer'):
        txt_type = aiodns.pycares.QUERY_TYPE_TXT
        raw = [rec.data.data for rec in dns_result.answer
               if rec.type == txt_type]
    else:
        raw = [rec.text for rec in dns_result]
    return list(filter_text(raw))

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-statements
class STSResolver:
    def __init__(self, *, timeout=defaults.TIMEOUT):
        self._timeout = timeout
        self._dns_resolver = None
        self._dns_query = None
        self._http_timeout = aiohttp.ClientTimeout(total=timeout)
        self._session = None
        self._proxy_info = aiohttp.helpers.proxies_from_env().get('https', None)
        self._logger = logging.getLogger("RES")

        if self._proxy_info is None:
            self._proxy = None
            self._proxy_auth = None
        else:
            self._proxy = self._proxy_info.proxy
            self._proxy_auth = self._proxy_info.proxy_auth

    async def _get_dns_query(self):
        # Created lazily so that it is always bound to the running
        # event loop, whatever loop the resolver happens to run in.
        if self._dns_resolver is None:
            self._dns_resolver = aiodns.DNSResolver(timeout=self._timeout)
            # query_dns() is preferred; query() is a deprecated alias
            # in newer aiodns versions but the only option in older ones.
            query = getattr(self._dns_resolver, 'query_dns', None)
            self._dns_query = (query if query is not None
                               else self._dns_resolver.query)
        return self._dns_query

    async def _get_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self._http_timeout)
        return self._session

    async def close(self):
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None
        if self._dns_resolver is not None:
            self._dns_resolver.cancel()
            self._dns_resolver = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-return-statements
    async def resolve(self, domain, last_known_id=None):
        if domain.startswith('.'):
            return STSFetchResult.NONE, None
        # Cleanup domain name
        domain = domain.rstrip('.')

        # Construct name of corresponding MTA-STS DNS record for domain
        sts_txt_domain = '_mta-sts.' + domain
        self._logger.debug("Got STS resolve request: sts_txt_domain=%s, "
                           "known_id=%s", sts_txt_domain, last_known_id)

        # Try to fetch it
        dns_query = await self._get_dns_query()
        try:
            txt_records = await asyncio.wait_for(
                dns_query(sts_txt_domain, 'TXT'),
                timeout=self._timeout)
        except aiodns.error.DNSError as error:
            if error.args[0] == aiodns.error.ARES_ETIMEOUT:  # pragma: no cover pylint: disable=no-else-return,no-member
                # This branch is not covered because of aiodns bug:
                # https://github.com/saghul/aiodns/pull/64
                # It's hard to decide what to do in case of timeout
                # Probably it's better to threat this as fetch error
                # so caller probably shall report such cases.
                return STSFetchResult.FETCH_ERROR, None
            elif error.args[0] == aiodns.error.ARES_ENOTFOUND:  # pylint: disable=no-else-return,no-member
                return STSFetchResult.NONE, None
            elif error.args[0] == aiodns.error.ARES_ENODATA:  # pylint: disable=no-else-return,no-member
                return STSFetchResult.NONE, None
            else:  # pragma: no cover
                return STSFetchResult.FETCH_ERROR, None
        except asyncio.TimeoutError:
            return STSFetchResult.FETCH_ERROR, None

        # Normalize the DNS answer to a flat list of text values (handles
        # both aiodns 3.x query() and aiodns >= 4.0 query_dns() return types).
        txt_records = _extract_txt_records(txt_records)

        # RFC 8461 strictly defines version string as first field
        txt_records = [txt for txt in txt_records
                       if txt.startswith('v=STSv1')]

        # Exactly one record should exist
        if len(txt_records) != 1:
            return STSFetchResult.NONE, None

        # Validate record
        mta_sts_record = parse_mta_sts_record(txt_records[0])
        if (mta_sts_record.get('v', None) != 'STSv1'
                or 'id' not in mta_sts_record):
            return STSFetchResult.NONE, None

        self._logger.debug("Parsed STS record for domain %s: %s",
                           repr(domain), repr(mta_sts_record))

        # Obtain policy ID and return NOT_CHANGED if ID is equal to last known
        if mta_sts_record['id'] == last_known_id:
            return STSFetchResult.NOT_CHANGED, None

        # Construct corresponding URL of MTA-STS policy
        sts_policy_url = ('https://mta-sts.' +
                          domain +
                          '/.well-known/mta-sts.txt')

        # Fetch actual policy
        try:
            session = await self._get_session()
            async with session.get(sts_policy_url,
                                   allow_redirects=False,
                                   proxy=self._proxy, headers=_HEADERS,
                                   proxy_auth=self._proxy_auth) as resp:
                if resp.status != 200:
                    raise BadSTSPolicy()
                if not is_plaintext(resp.headers.get('Content-Type', '')):
                    raise BadSTSPolicy()
                if (int(resp.headers.get('Content-Length', '0')) >
                        HARD_RESP_LIMIT):
                    raise BadSTSPolicy()
                policy_file = BytesIO()
                while True:
                    chunk = await resp.content.read(CHUNK)
                    if not chunk:
                        break
                    if policy_file.tell() + len(chunk) > HARD_RESP_LIMIT:
                        raise BadSTSPolicy()
                    policy_file.write(chunk)
                charset = (resp.charset if resp.charset is not None
                           else 'utf-8')
                policy_text = policy_file.getvalue().decode(charset)
        except Exception as exc:
            self._logger.warning("STS policy fetch for domain %s failed with "
                                 "error: %s", repr(domain), str(exc))
            return STSFetchResult.FETCH_ERROR, None

        # Parse policy
        pol = parse_mta_sts_policy(policy_text)

        self._logger.debug("Parsed policy for domain %s: %s", domain, repr(pol))

        # Validate policy
        if pol.get('version', None) != 'STSv1':
            return STSFetchResult.FETCH_ERROR, None

        try:
            max_age = int(pol.get('max_age', '-1'))
            pol['max_age'] = max_age
        except ValueError:
            return STSFetchResult.FETCH_ERROR, None

        if not 0 <= max_age <= 31557600:
            return STSFetchResult.FETCH_ERROR, None

        if 'mode' not in pol:
            return STSFetchResult.FETCH_ERROR, None

        # No MX check required for 'none' policy:
        if pol['mode'] == 'none':
            return STSFetchResult.VALID, (mta_sts_record['id'], pol)

        if pol['mode'] not in ('none', 'testing', 'enforce'):
            return STSFetchResult.FETCH_ERROR, None

        if not pol['mx']:
            return STSFetchResult.FETCH_ERROR, None

        # Policy is valid. Returning result.
        return STSFetchResult.VALID, (mta_sts_record['id'], pol)
