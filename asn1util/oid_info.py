import requests
from bs4 import BeautifulSoup
import json
from json.decoder import JSONDecodeError
import os
import logging


logger = logging.getLogger(__name__)

_CACHE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), r'.oid_cache'))
_SERVICE_URL = r'https://chenqiang.xyz/get/'  # http://oid-info.com/get/

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class OIDQueryService(metaclass=Singleton):
    def __init__(self):
        try:
            with open(_CACHE_FILE, 'r', encoding='utf-8') as file:
                self._local = json.load(file)
        except FileNotFoundError:
            self._local = {}
        except JSONDecodeError:
            self._local = {}

    def _query(self, oid: str, remote=True, force_remote=False):
        if not force_remote:
            if oid in self._local:
                return self._local[oid]
            elif not remote:
                return ("N/A", "N/A")

        try:
            resp = requests.get(_SERVICE_URL + oid, timeout=5)
            bs = BeautifulSoup(resp.text, 'lxml')
            if (len(bs.select('tr[bgcolor="#CCCCCC"]'))) == 0:
                return None

            notion = bs.select('tr[bgcolor="#CCCCCC"]')[0].select('textarea')[0].text
            description = bs.select('tr[bgcolor="#CCCCCC"]')[1].select('table td')[2].text.strip()

            self._local[oid] = (notion, description)
            with open(_CACHE_FILE, 'w', encoding='utf-8') as file:
                json.dump(self._local, file, ensure_ascii=False)

        except requests.RequestException as ex:
            logger.warning(f'Remote Query Exception: {str(ex)}')
            return ("N/A*", "N/A*")

        return self._local[oid]


    @staticmethod
    def query(oid: str, remote=True, force_remote=False):
        return OIDQueryService()._query(oid, remote, force_remote)
