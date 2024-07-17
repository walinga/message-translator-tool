import json
import re
from operator import itemgetter
from collections import OrderedDict
from urllib.request import urlopen
from bs4 import BeautifulSoup

PAR_DELTA_BUFFER = 3
DEBUG = False

# Removes punctuation from the given string
def strip_punctuation(s):
    return re.sub(r'[^\w]','',s)

# Splits a string on whitespace and another punctuation-like characters
def split_string(s):
    # TODO: Determine full list of characters to split on
    return list(filter(None, re.split(r'[\s…?\.“”]+', s)))

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
        'word_index_map': word_index_map
    }

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
        if quote_words[0] == chunk[0]:
            score += 1

        if score >= max_score:
            max_score = score
            quote_index = start_i

    quote_end_index = quote_index + quote_len
    best_match = english_text[word_index_map[quote_index] : word_index_map[quote_end_index]]
    print('[Best match]', best_match)

    # Determine start/end paragraph
    start_pnum = 1
    end_pnum = -1
    prev_index = -1
    prev_pnum = -1
    for pnum, index in pnum_map.items():
        if quote_index >= index:
            start_pnum = pnum
        if quote_end_index >= index:
            end_pnum = pnum + 1
        prev_index = index
   
    start_delta_back = quote_index - pnum_map[start_pnum]
    start_delta_forward = pnum_map[start_pnum+1] - quote_index
    start_delta_buffer = 0 if start_delta_back <= 1 else PAR_DELTA_BUFFER
    if start_delta_back < start_delta_forward:
        spanish_quote_start = pnum_map_es[start_pnum] + start_delta_back - start_delta_buffer
    else:
        spanish_quote_start = pnum_map_es[start_pnum+1] - start_delta_forward - start_delta_buffer

    end_delta_back = pnum_map[end_pnum] - quote_end_index
    end_delta_forward = quote_end_index - pnum_map[end_pnum-1]
    end_delta_buffer = 0 if end_delta_forward <= 1 else PAR_DELTA_BUFFER
    if end_delta_back < end_delta_forward:
        spanish_quote_end = pnum_map_es[end_pnum] - end_delta_back + end_delta_buffer
    else:
        spanish_quote_end = pnum_map_es[end_pnum-1] + end_delta_forward + end_delta_buffer

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
            'statusCode': 400
        }

    english_link = "https://www.messagehub.info/en/readMessage.msg?ref_num=" + message_id
    spanish_link = "https://www.messagehub.info/es/readMessage.msg?ref_num=" + message_id

    english_data = extract_text(english_link)
    spanish_data = extract_text(spanish_link)

    translation_data = determine_translation(quote, english_data, spanish_data)
    translation_data['source'] = spanish_link

    return {
        'statusCode': 200,
        'body': json.dumps(translation_data)
    }

# DEBUG
if __name__ == "__main__":
    DEBUG = True

    # resp = lambda_handler({
    #     'messageId': '60-0630',
    #     'quote': "God loves to fellowship with His creature. In the garden of Eden we are told, that when man walked in the uprightness of God, God came down in the cool of the evening and fellowshipped with His children. Then, one day there was a voice came up in the Presence of God and said, “Those Your loved ones, Your children, has fallen, and they have sinned and have did that which was wrong.” You know what…?…God didn’t just select some Angel to go down and look it over, to see if it was so or not, or a certain Cherubim of the heavens, but God came Hisself, crying, “Adam, where art Thou?” God, Himself, come crying for His lost child. When He found Him hiding in the bushes, behind sewed fig leaves, He said, “Who told you you were naked?” And he could not come out and have fellowship no more with God."
    #     }, {})
    # print(resp)


    # q = "She'd pass."
    # print(q.split())
    # print(split_string(q))
    # for w in q.split():
    #     print(strip_punctuation(w))