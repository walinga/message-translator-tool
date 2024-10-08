import json
import re
from operator import itemgetter
from collections import OrderedDict
from urllib.request import urlopen
from bs4 import BeautifulSoup

START_DELTA_BUFFER = 3
END_DELTA_BUFFER = 5
DEBUG = False

# Removes punctuation from the given string
def strip_punctuation(s):
    return re.sub(r'[^\w]','',s)

# Splits a string on whitespace and another punctuation-like characters
# Some characters common within words are NOT included, such as:
# - U+0027 : APOSTROPHE
# - U+002D : HYPHEN-MINUS
# - U+2019 : RIGHT SINGLE QUOTATION MARK
def split_string(s):
    return list(filter(None, re.split(r'[\s!"#$&\(\*\+,\.\/:;<=>?¡¢“”…—]+', s)))

# Extracts the full text from the provided link
# Returns an array of words
def extract_text(link):
    html_doc = urlopen(link).read()
    soup = BeautifulSoup(html_doc, 'html.parser')
    
    full_text = []
    for raw_str in soup.body.stripped_strings:
        full_text.append(raw_str)

    full_text_str = ' '.join(full_text)

    pnum_map = OrderedDict()
    for pnum_div in soup.find_all("div", class_="pnum"):
        par = pnum_div.parent
        par_text = ' '.join(par.strings)
        raw_text_index = full_text_str.find(par_text)
        key = int(pnum_div.string)
        pnum_map[key] = len(split_string(full_text_str[:raw_text_index]))

    words_list = split_string(full_text_str)
    pnum_map[key+1] = len(words_list)

    word_index_map = OrderedDict()
    cursor = 0
    for index, word in enumerate(words_list):
        pos = full_text_str[cursor:].index(word)
        word_index_map[index] = pos + cursor
        cursor += pos + len(word)
    word_index_map[len(words_list)] = len(full_text_str)

    return {
        'raw_text': full_text_str,
        'words_list': words_list,
        'pnum_map': pnum_map,
        'word_index_map': word_index_map,
        'title': soup.title.string
    }

def find_start_boundary(quote_index, pnum_map, pnum_map_es, prev_pnum, default_buffer):
    delta_back = quote_index - pnum_map[prev_pnum]
    delta_forward = pnum_map[prev_pnum+1] - quote_index
    delta_buffer = 0 if delta_back <= 1 else default_buffer
    if delta_back < delta_forward:
        es_boundary = pnum_map_es[prev_pnum] + delta_back
    else:
        es_boundary = pnum_map_es[prev_pnum+1] - delta_forward
    return {
        'es_boundary': es_boundary,
        'delta_buffer': delta_buffer
    }

def find_end_boundary(quote_index, pnum_map, pnum_map_es, prev_pnum, default_buffer):
    delta_back = quote_index - pnum_map[prev_pnum]
    delta_forward = pnum_map[prev_pnum+1] - quote_index
    delta_buffer = 0 if delta_back < 10 or delta_forward < 10 else default_buffer
    if delta_back < delta_forward:
        es_boundary = pnum_map_es[prev_pnum] + (0 if delta_back < 10 else delta_back)
    else:
        es_boundary = pnum_map_es[prev_pnum+1] - (0 if delta_forward < 10 else delta_forward)
    return {
        'es_boundary': es_boundary,
        'delta_buffer': delta_buffer
    }

# Determines the expected start of the spanish quote
#  -> If the english quote starts with a capital letter, find a capitalized spanish word
#  -> Fall back to the default buffer
def determine_start_delta_buffer(english_word_list, spanish_word_list, quote_index, start_boundary_data):
    spanish_quote_start = start_boundary_data['es_boundary']
    default_buffer = start_boundary_data['delta_buffer']
    if english_word_list[quote_index][0].isupper():
        for i in range(spanish_quote_start - default_buffer, spanish_quote_start - 10, -1):
            word = spanish_word_list[i]
            if word[0].isupper():
                return spanish_quote_start - i

    return default_buffer


def determine_translation(quote, english_data, spanish_data):
    english_word_list, english_text, pnum_map, word_index_map = itemgetter('words_list', 'raw_text', 'pnum_map', 'word_index_map')(english_data)
    spanish_word_list, spanish_text, pnum_map_es, word_index_map_es = itemgetter('words_list', 'raw_text', 'pnum_map', 'word_index_map')(spanish_data)

    # Determine best match using "Sliding window" algorithm
    #  -> tokenize text and quote into lists of words
    #  -> check each possible chunk of words (chunk size = len(quote))
    #  -> choose the chunk with the most matching words
    trimmed_words = list(map(strip_punctuation, english_word_list))
    quote_words = list(map(strip_punctuation, split_string(quote)))
    quote_len = len(quote_words)
    quote_words_set = set(quote_words)
    quote_index = -1
    max_score = 0
    for start_i in range(len(english_word_list) - quote_len):
        chunk = trimmed_words[start_i : start_i + quote_len]
        chunk_words = set(chunk)

        # Compare number of matching words via set intersection
        score = len(quote_words_set & chunk_words)

        # Add an extra point if the first words match
        if quote_words[0].lower() == chunk[0].lower():
            score += 1

        # DEBUG
        # if start_i > pnum_map[21] and start_i < pnum_map[23]:
        #     print(chunk[0], chunk[-1], score)

        if score >= max_score:
            max_score = score
            quote_index = start_i

    quote_end_index = quote_index + quote_len
    best_match = english_text[word_index_map[quote_index] : word_index_map[quote_end_index]]
    print('[Best match]', best_match)

    # Determine start/end paragraph
    start_pnum = 1
    end_pnum = -1
    for pnum, index in pnum_map.items():
        if quote_index >= index:
            start_pnum = pnum
        if quote_end_index >= index:
            end_pnum = pnum + 1
   
    start_boundary_data = find_start_boundary(quote_index, pnum_map, pnum_map_es, start_pnum, START_DELTA_BUFFER)
    start_delta_buffer = determine_start_delta_buffer(english_word_list, spanish_word_list, quote_index, start_boundary_data)
    spanish_quote_start = start_boundary_data['es_boundary'] - start_delta_buffer

    end_boundary_data = find_end_boundary(quote_end_index, pnum_map, pnum_map_es, end_pnum - 1, END_DELTA_BUFFER)
    spanish_quote_end = min(len(spanish_word_list), end_boundary_data['es_boundary'] + end_boundary_data['delta_buffer'])

    translation = spanish_text[word_index_map_es[spanish_quote_start] : word_index_map_es[spanish_quote_end]]
    print('[Full translation]', translation)

    return {
        'quote': best_match,
        'translation': translation,
        'paragraphNumber': start_pnum
    }

def lambda_handler(event, context):
    message_id = event['messageId']
    quote = event['quote']
    if (len(message_id) > 15 or len(quote) > 100000):
        return {
            'statusCode': 400,
            'error': 'Either the Message ID or quote provided is too long'
        }

    english_link = "https://www.messagehub.info/en/readMessage.msg?ref_num=" + message_id
    spanish_link = "https://www.messagehub.info/es/readMessage.msg?ref_num=" + message_id

    try:
        english_data = extract_text(english_link)
        spanish_data = extract_text(spanish_link)
    except:
        return {
            'statusCode': 404,
            'error': 'Message ID [' + message_id + '] could not be found'
        }

    translation_data = determine_translation(quote, english_data, spanish_data)
    translation_data['source'] = spanish_link
    translation_data['messageInfo'] = {
        'messageId': message_id,
        'englishTitle': english_data['title'],
        'spanishTitle': spanish_data['title']
    }

    return {
        'statusCode': 200,
        'body': json.dumps(translation_data)
    }

# DEBUG
if __name__ == "__main__":
    DEBUG = True

    resp = lambda_handler({
        'messageId': '56-0801',
        # TODO: Debug quote start
        'quote': "You’ve got one of the best churches I ever walked into in my life of\nanywhere, on any continent. Life Tabernacle’s one of my favorites. It\nbreaks my heart to see you letting the world reach into you the way\nyou’re doing. So don’t do that no more. Snap out of it. Pray out of it,\nand let God come back and take over. Submit yourselves to God and get\nthe old fashion blessing back again.\nAnd I tell you, don’t let the world creep into you. Don’t let the world\nget into your churches, brethren. Pray it out, fast it out until God comes\ndown and takes a hold. That’s right. Keep the joy of the Lord among the\nsaints. Keep them prayed up. And guard every little place.\n"
        }, {})
    print(resp)

    # print(len(split_string("Let every unclean spirit that's in these people, every spirit of doubting, every spirit of fear, every denominational cling, every habit, every sickness, every disease that's among the people, leave; in the name of Jesus Christ may it come out of this group of people. And may they be free from this hour on, that they can eat the eagle food that we're believing You'll send us through the week, Lord, breaking open those Seals and showing us those mysteries that's been hid since the foundation of the world, as You promised. They are Yours, Father. In the name of Jesus Christ. Amen.")))
    # print(len(split_string("Permite que todo espíritu inmundo que está en estas personas, todo espíritu de duda, todo espíritu de temor, toda atadura denominacional, toda mala costumbre, toda enfermedad, toda dolencia que esté entre la gente, que se vaya. En el Nombre de Jesucristo, que eso salga de este grupo de personas. Y que ellos sean libres desde esta hora en adelante, para que ellos puedan comer el Alimento de Águila que estamos creyendo que Tú nos enviarás a través de la semana, Señor; abriendo esos Sellos y mostrándonos esos misterios que han sido escondidos desde la fundación del mundo, como Tú has prometido. Ellos son Tuyos, Padre. En el Nombre de Jesucristo. Amén.")))
    # for u in ["Aun", "Él", "we"]:
    #     print(u, u[0].isupper())

    q = """
    """
    # print(len(q.split()))
    # print(split_string(q))
    # for w in q.split():
    #     print(strip_punctuation(w))
    for i in split_string(q):
        if re.sub(r'[^\w\-\'’\[\]]','',i) != i:
            print(i)