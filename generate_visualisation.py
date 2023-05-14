from ioc_finder import find_iocs # https://pypi.org/project/ioc-finder/
from multi_rake import Rake # https://pypi.org/project/multi-rake/
from PIL import Image
import fractalanalysis
import numpy as np
import math
import imageio
import pickle
import re
import pprint
import cv2
import copy

PICKLE = "data/dump2.pickle"

data = pickle.load(open(PICKLE, "rb"))

posts = []
for i in data:
    for k in data[i]:
        print(k)
        for e in data[i][k]:
            print(e)
            posts.append(e)

pp = pprint.PrettyPrinter(indent=4)

def rake_en_phrases(string):
    rake = Rake(
        min_chars=10,
        max_words=3,
        min_freq=1,
        language_code='en',  # 'en'
        stopwords=None,  # {'and', 'of'}
        lang_detect_threshold=50,
        max_words_unknown_lang=2,
        generated_stopwords_percentile=80,
        generated_stopwords_max_len=3,
        generated_stopwords_min_freq=2, )
    keywords = rake.apply(string)
    return [x[0] for x in keywords]


def rake_en_words(string):
    rake = Rake(
        min_chars=4,
        max_words=1,
        min_freq=2,
        language_code='en',  # 'en'
        stopwords=None,  # {'and', 'of'}
        lang_detect_threshold=50,
        max_words_unknown_lang=2,
        generated_stopwords_percentile=80,
        generated_stopwords_max_len=3,
        generated_stopwords_min_freq=2, )
    keywords = rake.apply(string)
    return [x[0] for x in keywords]


def rake_ru_phrases(string):  # extract keywords
    # rake = Rake()
    rake = Rake(
        min_chars=10,
        max_words=3,
        min_freq=1,
        language_code='ru',  # 'en'
        stopwords=None,  # {'and', 'of'}
        lang_detect_threshold=50,
        max_words_unknown_lang=2,
        generated_stopwords_percentile=80,
        generated_stopwords_max_len=3,
        generated_stopwords_min_freq=2, )
    keywords = rake.apply(string)
    return [x[0] for x in keywords]


def rake_ru_words(string):  # extract keywords
    # rake = Rake()
    rake = Rake(
        min_chars=4,
        max_words=1,
        min_freq=2,
        language_code='ru',  # 'en'
        stopwords=None,  # {'and', 'of'}
        lang_detect_threshold=50,
        max_words_unknown_lang=2,
        generated_stopwords_percentile=80,
        generated_stopwords_max_len=3,
        generated_stopwords_min_freq=2, )
    keywords = rake.apply(string)
    return [x[0] for x in keywords]


# Custom dictionary: English and Russian translation
word_dictionary = "ransomware", "bots", "trojan", "virus", " threat ", "government", "botnet", "attack", "attacker", \
                  "antivirus", "app", "attacker", "botnet", "breach", "browser", "brute force attack", "certificate", \
                  "cloud", "credentials", "cyber attack", "dictionary attack", "dos", "denial of service", "download attack", \
                  "encryption", "exploit", "firewall", "hacker", "honeypot", "iot", "malware", "network", "patching", "pentest", \
                  "phising", "pharming", "platform", "router", "software as a service", "saas", "smishing", "social engineering",\
                  "spear phishing", "two-factor authentication", "2fa", "vpn", "virtual private network", "vulnerability",\
                    "whaling", "water-holing", "zero-day","Программы-вымогатели", "боты", "троян", "вирус", "угроза", "правительство", "ботнет", "атака", "змышленник", \
                   "Антивирус", "приложение", "злоумышленник", "ботнет", "нарушение", "браузер", "атака методом грубой силы", "сертификат", \
                   "облако", "учетные данные", "кибератака", "атака по словарю", "дос", "отказ в обслуживании", "атака загрузки", \
                   "Шифрование", "эксплойт", "брандмауэр", "хакер", "приманка", "iot", "вредоносное ПО", "сеть", "исправление", "пентест", \
                   "Фисинг", "фарминг", "платформа", "маршрутизатор", "программное обеспечение как услуга", "саас", "смишинг", "социальная инженерия", \
                   "Целевой фишинг", "двухфакторная сеть аутентичной", "2fa", "vpn", "виртуальная частная", "уязвимость", \
                     "китобойный промысел", "водозабор", "нулевой день", "python", "c++", "delphi", "0day"\

# filter all types from list that aren't strings
posts = [x for x in posts if isinstance(x, str)]

#filter strings that are less than 200 characters
posts = [x for x in posts if len(x) > 500]

code_post = []
# for the first 100 posts, return posts containing ***CODE*** (for testing)
for post in posts[:100]:
    if '***CODE***' in post:
        code_post.append(post)

price_post = []
# for the first 100 posts, return posts containing '$' (for testing)
for post in posts[:100]:
    if '$' in post:
        price_post.append(post)

# given a list of substrings, replace them in another string with a given ID
def replace_substrings(string, substrings, ID):
    for substring in substrings:
        substring = substring.lower()
        string = string.replace(substring, ID)
    return string


''' feature precedence matters,  
i.e. detect in order of priorities (rake detect-> ioc detect -> ioc replace 
-> question detect/replace -> keyword/key phrase rake replace -> currency detect/replace -> code detect/replace)
'''
def analyse_post(post):
    # make post lowercase
    original_post = str(post)
    post = post.lower()

    # Initial rake phase before any modifications
    ru_words = rake_ru_words(post)
    en_words = rake_en_words(post)
    ru_phrases = rake_ru_phrases(post)
    en_phrases = rake_en_phrases(post)

    # find IOCs with ioc-finder
    iocs = find_iocs(post)
    print(iocs)

    post = replace_substrings(post, iocs['cves'], ' CVE_PIXEL ')

    def find_urls(string):
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        found_urls = re.findall(url_pattern, string)
        return found_urls

    post = replace_substrings(post, find_urls(post), ' URL_PIXEL ')
    post = replace_substrings(post, iocs['urls'], ' URL_PIXEL ')
    post = replace_substrings(post, iocs['ipv4s'], ' IPV4_PIXEL ')
    post = replace_substrings(post, iocs['ipv6s'], ' IPV6_PIXEL ')

    post = replace_substrings(post, iocs['email_addresses_complete'], ' EMAIL_PIXEL ')
    post = replace_substrings(post, iocs['email_addresses'], ' EMAIL_PIXEL ')
    post = replace_substrings(post, iocs['xmpp_addresses'], ' XMPP_PIXEL ')

    def detect_telegram_handle(text):
        pattern = r'@(?!_)(?!.*__)(?!.*_$)[A-Za-z0-9_]{5,32}'
        telegram_handles = re.findall(pattern, text)
        return telegram_handles

    telegram_handles = detect_telegram_handle(post)
    post = replace_substrings(post, telegram_handles, ' TELEGRAM_PIXEL ')
    post = re.sub(r'^(?:((\+?\d{2,3})|(\(\+?\d{2,3}\))) ?)?(((\d{2}[\ \-\.]?){3,5}\d{2})|((\d{3}[\ \-\.]?){2}\d{4}))$', ' PHONE_PIXEL ', post)

    post = replace_substrings(post, iocs['domains'], ' DOMAIN_PIXEL ')

    post = replace_substrings(post, iocs['bitcoin_addresses'], ' BTC_PIXEL ')
    post = replace_substrings(post, iocs['monero_addresses'], ' MONERO_PIXEL ')

    def detect_unix_path(text):
        pattern = r'^\/$|(^(?=\/)|^\.|^\.\.)(\/(?=[^/\0])[^/\0]+)*\/?$'
        unix_path = re.findall(pattern, text)
        return unix_path
    paths = detect_unix_path(post)
    #replace_substrings(post, paths, ' FP_PIXEL ')

    def detect_windows_path(text):
        pattern = r'(^([a-z]|[A-Z]):(?=\\(?![\0-\37<>:"/\\|?*])|\/(?![\0-\37<>:"/\\|?*])|$)|^\\(?=[\\\/][^\0-\37<>:"/\\|?*]+)|^(?=(\\|\/)$)|^\.(?=(\\|\/)$)|^\.\.(?=(\\|\/)$)|^(?=(\\|\/)[^\0-\37<>:"/\\|?*]+)|^\.(?=(\\|\/)[^\0-\37<>:"/\\|?*]+)|^\.\.(?=(\\|\/)[^\0-\37<>:"/\\|?*]+))((\\|\/)[^\0-\37<>:"/\\|?*]+|(\\|\/)$)*()$'
        windows_path = re.findall(pattern, text)
        return windows_path

    post = replace_substrings(post, iocs['file_paths'], ' FP_PIXEL ')
    post = replace_substrings(post, iocs['asns'], ' ASN_PIXEL ')
    post = replace_substrings(post, iocs['md5s'], ' MD5_PIXEL ')
    post = replace_substrings(post, iocs['sha1s'], ' SHA1_PIXEL ')
    post = replace_substrings(post, iocs['sha256s'], ' SHA256_PIXEL ')
    post = replace_substrings(post, iocs['sha512s'], ' SHA512_PIXEL ')
    post = replace_substrings(post, iocs['authentihashes'], ' AUTHENTIHASH_PIXEL ')
    post = replace_substrings(post, iocs['ipv4_cidrs'], ' CIDR_PIXEL ')
    post = replace_substrings(post, iocs['md5s'], ' MD5_PIXEL ')
    post = replace_substrings(post, iocs['registry_key_paths'], ' REGISTRY_PIXEL ')

    # example code patterns (to be completed)
    common_patterns = [
        # Assembly Language
        ' MOV ', ' SUB ', ' CMP ', ' JMP ', ' JE ', ' JNE ', ' JZ ', ' JNZ ', ' RET ', ' POP ', ' INC ', ' DEC ', ' XOR ', 'esi', 'eax', ' proc ', ' dword ' ,
        
        #etc
        ' invoke ', ' stdcall ',
        '$dir', '$file', '$line', '$this', '$self', '$class', '$function', '$method', '$namespace', '$interface',
        '$trait', '$goto', '$switch', '$case', '$default', '$break', '$continue', '$return', '$throw', '$try', '$str'                                                                                             

        # C/C++
        ' int ', ' float ', ' char ', ' void ', ' const ', ' bool ', ' struct ', ' union ', ' enum ', ' typedef ', ' sizeof ', ' NULL ',

        # Python
        ' print ',  ' elif ',  ' def ', ' class ', ' import ', ' lambda ', ' var '

        # Java
        ' static ', ' void ', ' int ', ' float ',
        ' char ', ' boolean ', ' class ', ' abstract ', ' enum '
    
        ' **argv ', '<iostream>', '<windows.h>']

    code_placeholders = [
        '$var', '$value', '$num', '$index', '$item', '$key', '$result', '$output', '$data', '$input',
        '$param', '$args', '$kwargs', '$config', '$settings', '$options', '$message', '$error', '$exception',
        '$response', '$request', '$file', '$path', '$dir', '$folder', '$name', '$url', '$uri', '$host',
        '$port', '$user', '$password', '$token', '$auth', '$session', '$database', '$table', '$column',
        '$query', '$sql', '$condition', '$filter', '$regex', '$pattern', '$match', '$replacement', '$target',
        '$source', '$destination', '$source_file', '$target_file', '$source_dir', '$target_dir']

    post = replace_substrings(post, common_patterns, ' CODE_PHRASE_PIXEL ')
    post = replace_substrings(post, code_placeholders, ' CODE_PHRASE_PIXEL ')

    def detect_snake_case(text):
        pattern = r'[a-z\d]+(?:_[a-z\d]+)*'
        snake_case_phrases = re.findall(pattern, text)
        return snake_case_phrases

    snake_case_phrases = detect_snake_case(post)
    replace_substrings(post, snake_case_phrases, ' VARIABLE_PIXEL ')

    def detect_camel_case(text):
        pattern = r'[A-Z][a-z\d]+(?:[A-Z][a-z\d]+)*'
        camel_case_phrases = re.findall(pattern, text)
        return camel_case_phrases

    camel_case_phrases = detect_camel_case(post)
    replace_substrings(post, camel_case_phrases, ' VARIABLE_PIXEL ')


    # replace matches with custom dictionary
    post = replace_substrings(post, word_dictionary, ' DICT_KW_PIXEL ')
    # replace matches with rake extraction
    '''
    for e in en_phrases:
        #If there isn't a space, don't consider as a phrase
        if e.find(" ") == -1:
            #print(e[0])
            print("removed rakeEnPhrase")
        else:
            #print(e[0])
            post = post.replace(e, ' EN_KP-PIXEL ')

    for e in ru_phrases:
        #If there isn't a space, don't consider as a phrase
        if e.find(" ") == -1:
            #print(e[0])
            print("removed rakeEnPhrase")
        else:
            #print(e[0])
            post = post.replace(e, ' RU_KP-PIXEL ')

    for e in en_words:
        #If not alphanumeric, remove (introduce bias against detection of some technical noise being registered as keywords)
        if not e.isalnum():
            print("removed rakeEnWords")
            print(e)
        else:
            print(e)
            post = post.replace(e, ' EN_KW_PIXEL ')

    for e in ru_words:
        #If not alphanumeric, remove (introduce bias against detection of some technical noise being registered as keywords)
        if not e.isalnum():
            print("removed rakeEnWords")
            print(e)
        else:
            print(e)
            post = post.replace(e, ' RU_KW_PIXEL ')'''

    # replace any number of question marks with a single QUESTION_PIXEL
    post = re.sub(r'\?+', ' QUESTION_PIXEL ', post)

    # forum tags for particular forum
    # replace occurrence of ***CODE*** with CODE_PIXEL
    post = post.replace('***code***', ' CODE_TAG_PIXEL ')
    post = post.replace('***link***', '')
    post = post.replace('***img***', '')

    # update to forex_python at some point
    # currency symbols and abbreviations
    currency_strings = [
        'USD', 'доллары', 'бакс', 'американские доллары', 'доллар', '$',
        'EUR', 'евро', 'евр', '€',
        'JPY', 'иены', 'йена', '¥',
        'GBP', 'фунты', 'стерлинги', 'британские фунты', 'фунт', '£',
        'AUD', 'австралийские доллары', 'австралийский доллар', 'ауд', 'а$',
        'CAD', 'канадские доллары', 'канадский доллар', 'кад', 'с$', 'к$',
        'CHF', 'швейцарские франки', 'швейцарский франк',
        'CNY', 'юани', 'китайские юани', 'ренминби', 'йен', '¥',
        'RUB', 'рубли', 'рубль', '₽',
        'INR', 'рупии', 'индийские рупии', '₹',
        'BTC', 'биткоины', 'биткойн', 'биток', 'биты', 'бтк', '₿'
    ]

    # proof of concept, can be improved with various libaries.
    '''
    cryptocurrency_notations = [
        'криптовалюта', 'крипта', 'криптовалюты', 'цифровая валюта', 'криптоденьги', 'биткойн', 'биткоин', 'биткойны',
        'эфириум', 'эфир',
        'рипл', 'лайткойн', 'лайткоин', 'догекоин', 'доджкоин', 'монеро', 'зетекоин', 'нано', 'кардано', 'тезер',
        'биткэш', 'дэш', 'нео',
        'тезор', 'стилар', 'эксмо', 'кукуруза', 'кукумар', 'кукумарс', 'титан', 'титаны', 'фак', 'факи', 'факкоины',
        'токены', 'токен',
        'токены', 'сатоши', 'сатошей', 'сатоши', 'альткоины', 'фьючерсы', 'майнинг', 'майнеры', 'майнить', 'хешрейт',
        'пулы', 'криптобиржа',
        'трейдинг', 'трейдеры', 'холдеры', 'криптоплатформа', 'блокчейн', 'ICO', 'токенсейл', 'смарт-контракты',
        'дайджест', 'баг', 'вандал',
        'хардфорк', 'софтфорк', 'майннет', 'тестнет', 'бычки', 'медведи', 'быки', 'вынос', 'флуд', 'скам', 'дамп',
        'памп', 'холд',
        'транзакции', 'блоки', 'кошельки', 'кошелек', 'приватные ключи', 'публичный ключ', 'приватный ключ',
        'приватные ключи',
        'криптоанархия', 'анонимность', 'псевдоним', 'переводы', 'платежи', 'транзакционный граф',
        'транзакционный журнал', 'блок',
        'блокчейн-технологии', 'майнерство', 'майнер', 'майнинг-ферма', 'майнинг'
    ]'''

    currency_symbols = ['$', '€', '£', '₹', '¥', '₣', '₽', '₺', '₴', '₦', '₨', '₩', '₱', '₲', '₪', '₵', '¢', '₡', '₫', '₿', '₢', '₸', '฿', '៛', '₥', '₤', '₠', '₧', '₯']
    currency_abbreviations = ['btc', 'usd', 'gbp', 'eur', 'rub', 'btc', 'eth', 'ltc', 'xmr', 'zec', 'dash', 'bch', 'xrp', 'xlm']
    currency_expanded = ['dollar', 'pound', 'euro', 'ruble', 'bitcoin', 'etherium', 'litecoin', 'monero', 'zcash']
    post = re.sub(r'(?:dollar[s]?|\$)\s*(\d+)|(\d+)\s*(?:dollar[s]?|\$)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:usd[s]?|\$)\s*(\d+)|(\d+)\s*(?:usd[s]?|\$)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:pound[s]?|\£)\s*(\d+)|(\d+)\s*(?:pound[s]?|\£)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:btc[s]?|\฿)\s*(\d+)|(\d+)\s*(?:btc[s]?|\฿)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:bitcoin[s]?|\฿)\s*(\d+)|(\d+)\s*(?:bitcoin[s]?|\฿)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:eur[s]?|\€)\s*(\d+)|(\d+)\s*(?:eur[s]?|\€)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:euro[s]?|\€)\s*(\d+)|(\d+)\s*(?:euro[s]?|\€)', ' PRICE_PIXEL ',  post)
    post = re.sub(r'(?:руб[лей]?|\₽)\s*(\d+)|(\d+)\s*(?:руб[лей]?|\₽)', ' PRICE_PIXEL ',  post)
    post = replace_substrings(post, currency_strings, ' PRICE_PIXEL ')
    post = replace_substrings(post, currency_symbols, ' PRICE_PIXEL ')
    post = replace_substrings(post, currency_abbreviations, ' PRICE_PIXEL ')
    post = replace_substrings(post, currency_expanded, ' PRICE_PIXEL ')

    # can add a threshold trigger (i.e. only activate past a number of symbols detected, to avoid natural language posts)
    post = replace_substrings(post, ru_phrases, ' RU_KP_PIXEL ')
    post = replace_substrings(post, en_phrases, ' EN_KP_PIXEL ')
    post = replace_substrings(post, ru_words, ' RU_KW_PIXEL ')
    post = replace_substrings(post, en_words, ' EN_KW_PIXEL ')

    # operators/symbols used in code but not usually in text
    symbols = [
        '%s', '%d', '%f', '%c', '%u', '%x', '%o', '%e', '%g', '%p', '%a', '%n',
        '!=', '<', '>', '<=', '>=', '">', '<"', '="', '</', '/>', '});', '})', '({', ');', '){', ') {',
        ' && ', '||', ' ~ ',
        '<<', '>>',
        '+=', ' -= ', '*=', '/=', '%=',
        '[]', '{}', '()', '<>', '::', '->']

    # for only looking at code
    '''
    symbols_noisy = [
        '+', '-', '* ', '/', '%', 
        '++', '--',
        '==', '!=', '<=', '>=',
        '&&', '||', '&', '|', '^', '~',
        '<<', '>>',
        '+=', '-=', '*=', '/=', '%=',
        '::', '->', '?:',
        '{}', '[]', '()', '<>',
        '\\', ';', '#'
    ]'''

    # can activate patterns only if over a threshold of symbols detected
    post = replace_substrings(post, symbols, ' CODE_SYMBOL_PIXEL ')

    # exentions of files commonly found in forum and code segments
    file_extensions = [
        '.php', '.js', '.html', '.css', '.py', '.c ', '.cpp', '.h ', '.java', '.class', '.jar', '.sh', '.bat',
        '.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt',
        '.csv', '.xls', '.xlsx', '.ods', '.json', '.xml', '.sql', '.db', '.mdb',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff',
        '.mp3', '.wav', '.ogg', '.flac', '.m4a',
        '.mp4', '.avi', '.mov', '.flv', '.mkv',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso',
        '.exe', '.dll', '.bin', '.sys', '.tmp',
        '.log', '.ini', '.conf', '.reg', '.cer', '.key', '.pem',
        '.ps1', '.vbs', '.cmd', '.wsf', '.asp', '.aspx', '.jsp', '.jspx',
        '.swf', '.fla', '.actionscript',
        '.rb', '.pl', '.cgi', '.lua',
        '.go ', '.swift', '.r ', '.m ', '.rs',
        '.md', '.rst', '.tex',
        '.torrent',
        '.onion',
        '.btc', '.eth',
        '.apk', '.ipa', '.app', '.dmg', '.pkg', '.deb', '.rpm', '.msi', '.appx', '.appxbundle', '.xap',
        '.out', '.o ', '.obj', '.elf', '.so ', '.a ', '.lib', '.pdb', '.exp', '.map', '.def', '.res', '.rc']

    post = replace_substrings(post, file_extensions, ' EXTENSIONS_PIXEL ')

    # split post around whitespace
    post = post.split()

    return post, original_post


def render_thumbnail(post, metadata, outfile):
    print(post)
    dim = int(math.ceil(math.sqrt(len(post))))

    grid = np.zeros((dim,dim,3), dtype=np.uint8 )
    grid[np.all(grid == (0, 0, 0), axis=-1)] = (255,255,255)

    def duplicates(lst, item):
        return [i for i, x in enumerate(lst) if x == item]

    def replace_elements_in_list(lst, old, new):
        for i, e in enumerate(lst):
            if e in old:
                lst[i] = new
        return lst

    intermediate_post = copy.deepcopy(post)

    #Group specific traits into one colour
    replace_elements_in_list(post,['EN_KP_PIXEL', 'RU_KP_PIXEL', 'EN_KW_PIXEL', 'RU_KW_PIXEL', 'DICT_KW_PIXEL'], 'RED-PIXEL')
    replace_elements_in_list(post,['URL_PIXEL', 'DOMAIN_PIXEL', 'IPV4_PIXEL', 'IPV6_PIXEL'], 'BLUE-PIXEL')
    replace_elements_in_list(post, ['XMPP_PIXEL', 'EMAIL_PIXEL', 'PHONE_PIXEL', 'TELEGRAM_PIXEL'], 'CYAN-PIXEL')
    replace_elements_in_list(post,['PRICE_PIXEL', 'BTC_PIXEL', 'MONERO_PIXEL'], 'PURPLE-PIXEL')
    replace_elements_in_list(post, ['CODE_TAG_PIXEL'], 'GREEN-PIXEL')
    replace_elements_in_list(post, ['CODE_SYMBOL_PIXEL', 'CODE_PHRASE_PIXEL', 'VARIABLE_PIXEL'], 'LIGHTGREEN-PIXEL')
    replace_elements_in_list(post, ['QUESTION_PIXEL'], 'YELLOW-PIXEL')
    replace_elements_in_list(post, ['EXTENSIONS_PIXEL'], 'ORANGE-PIXEL')

    #rarer traits
    replace_elements_in_list(post, ['FP_PIXEL', 'MD5_PIXEL', 'SHA1_PIXEL', 'SHA256_PIXEL', 'SHA_512_PIXEL', 'AUTHENTIHASH_PIXEL', 'ASN_PIXEL', 'CIDR_PIXEL', 'REGISTRY_PIXEL'], 'LIGHTBLUE-PIXEL')
    replace_elements_in_list(post, ['CVE_PIXEL'], 'GREY-PIXEL')

    red_pixel_list = duplicates(post, "RED-PIXEL")
    blue_pix_list = duplicates(post, "BLUE-PIXEL")
    yellow_pix_list = duplicates(post, "YELLOW-PIXEL")
    green_pix_list = duplicates(post, "GREEN-PIXEL")
    purple_pix_list = duplicates(post, "PURPLE-PIXEL")
    cyan_pix_list = duplicates(post, "CYAN-PIXEL")
    orange_pix_list = duplicates(post, "ORANGE-PIXEL")
    threat_pix_list = duplicates(post, "THREAT-PIXEL")
    light_blue_pix_list = duplicates(post, "LIGHTBLUE-PIXEL")
    grey_pix_list = duplicates(post, "GREY-PIXEL")
    light_green_pix_list = duplicates(post, "LIGHTGREEN-PIXEL")

    for e in red_pixel_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [255,0,0]

    for e in blue_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [0,0,255]

    for e in light_blue_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [173,216,230]

    for e in yellow_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [255,255,0]

    for e in green_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [0,255,0]

    for e in light_green_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [144,238,144]

    for e in purple_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [255,0,255]

    for e in cyan_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [0,255,255]

    for e in orange_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [255,165,0]

    for e in threat_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [200,0,0]

    for e in grey_pix_list:
            row = e // dim
            column = e % dim
            grid[row][column] = [128,128,128]

    img = Image.fromarray(grid)
    img.save(outfile)

    image = cv2.imread(outfile, 0)
    I = imageio.imread(outfile, mode='L') / 255.0

    #modify threshold to filter features
    fd = "{:.2f}".format(round(fractalanalysis.fractal_dimension(I, threshold=0.8), 2))
    print(f"Fractal dimension: {fd}")

    with open(outfile + "fd: " +  fd + '.txt', 'w') as f:
        f.write("fractal dimension was computed at: " + str(fd))
        f.write("\n")
        f.write(str(metadata))
        f.write("\n")
        f.write("---------------------------------------------")
        f.write("\n")
        f.write(str(post))
        f.write("\n")
        f.write("---------------------------------------------")
        f.write('\n")
        f.write(str(intermediate_post))


count = 0
for e in posts:
    render_thumbnail(analyse_post(e)[0], analyse_post(e)[1], 'directory_test/' + str(count) + '.png')
    count += 1
